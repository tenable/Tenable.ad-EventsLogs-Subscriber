use crate::configuration::{Arguments, EventsLogsConfiguration};
use crate::constants::VERSION;
use crate::sharing::errors::FileSharingError;
use crate::sharing::errors::FileSharingFailureReason::FileTransferFailed;
use crate::sharing::file_sharing::*;
use crate::sharing::file_sharing_metrics::FileSharingMetrics;
use crate::sharing::smb::implementation::SmbFileSharing;
use crate::sharing::sysvol::implementation::SysvolFileSharing;
use flate2::{Compression, GzBuilder};
use log::{debug, info};
use std::io::Write;
use std::time::SystemTime;

macro_rules! create_file_sharing_mode {
    ($implementation:expr, $arguments:expr, $configuration:expr) => {
        match $implementation {
            FileSharingMode::SMB => FileSharingImplementation::SmbFileSharing(SmbFileSharing::new(
                $arguments,
                $configuration,
            )),
            FileSharingMode::SYSVOL => FileSharingImplementation::SysvolFileSharing(
                SysvolFileSharing::new($arguments, $configuration),
            ),
        }
    };
}

macro_rules! call_current_file_sharing_mode {
    ($implementation:expr, $method:ident, $($args:expr),*) => {
        match $implementation {
            FileSharingImplementation::SmbFileSharing(ref mut inner) => inner.$method($($args),*),
            FileSharingImplementation::SysvolFileSharing(ref mut inner) => inner.$method($($args),*),

            #[cfg(test)]
            FileSharingImplementation::MockFileSharing(ref mut inner) => inner.$method($($args),*),
        }
    };
    ($implementation:expr, $method:ident) => {
        match $implementation {
            FileSharingImplementation::SmbFileSharing(ref mut inner) => inner.$method(),
            FileSharingImplementation::SysvolFileSharing(ref mut inner) => inner.$method(),

            #[cfg(test)]
            FileSharingImplementation::MockFileSharing(ref mut inner) => inner.$method(),
        }
    };
}

/// All available implementations of different file sharing methods
pub enum FileSharingImplementation {
    SmbFileSharing(SmbFileSharing),
    SysvolFileSharing(SysvolFileSharing),
    #[cfg(test)]
    MockFileSharing(MockFileSharing),
}

pub struct FileSharingManager {
    current_mode: FileSharingMode,
    file_sharing: FileSharingImplementation,
    original_args: Arguments,
    metrics: FileSharingMetrics,
}

impl FileSharingManager {
    pub(crate) fn new(
        is_pdc: bool,
        args: Arguments,
        configuration: &EventsLogsConfiguration,
    ) -> Self {
        let current_mode = Self::get_desired_file_sharing_mode_from_config(configuration);
        let mut implementation = create_file_sharing_mode!(current_mode, &args, configuration);
        call_current_file_sharing_mode!(implementation, set_is_pdc, is_pdc);
        info!("Starting initial file sharing mode: {current_mode:?}");
        Self {
            current_mode,
            file_sharing: implementation,
            original_args: args,
            metrics: FileSharingMetrics::default(),
        }
    }

    pub fn start(
        &mut self,
        is_pdc: bool,
        configuration: &EventsLogsConfiguration,
    ) -> Result<(), FileSharingError> {
        if is_pdc && self.current_mode != FileSharingMode::SMB {
            // This is a "best-effort" attempt at deleting traces of a potential remaining SMB server
            // We are doing this here as it's possible the execution was stopped and the switch from SMB to SYSVOL happened when the listener was not running
            info!("Calling SMB disable method to remove potential remaining SMB share that couldn't be cleaned during previous run");
            let mut tmp_smb_impl = SmbFileSharing::new(&self.original_args, &configuration);
            tmp_smb_impl.set_is_pdc(is_pdc);
            let _ = tmp_smb_impl.disable();
        }
        return call_current_file_sharing_mode!(self.file_sharing, setup);
    }

    pub fn send_file(
        &mut self,
        enable_gzip: &bool,
        file_path: &String,
        file_content: &Vec<u8>,
    ) -> Result<(), FileSharingError> {
        if file_content.is_empty() {
            debug!("No Windows events buffered to dump, skipping operation");
            return Ok(());
        }
        let initial_size = file_content.len();
        let mut compressed_size = file_content.len() as i64;
        let write_result: Result<String, FileSharingError>;
        self.metrics.increment_file_generation();

        if *enable_gzip {
            let compression_level = Compression::default(); // This is level 6 out of 9
            let mut gz_encoder = GzBuilder::new()
                .mtime(
                    SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32,
                )
                .extra(self.metrics.get_current_generation().to_be_bytes()) // This will let us see if we "missed" a file on the destination or while debugging
                .comment(VERSION)
                .write(Vec::new(), compression_level);

            gz_encoder.write_all(&file_content).map_err(|write_err| FileSharingError {
                error: FileTransferFailed,
                description: format!("[{}] Could not write file content to gz stream, got '{:?}'. The file will not be created.", self.metrics.get_current_generation(), write_err)
            })?;

            match gz_encoder.finish() {
                Ok(gz_content) => {
                    compressed_size = gz_content.len() as i64;
                    write_result = call_current_file_sharing_mode!(
                        self.file_sharing,
                        try_flush_events_to_file,
                        file_path,
                        &gz_content
                    )
                }
                // Should not happen in theory but who knows ...
                Err(finish_err) => {
                    return Err(FileSharingError {
                        error: FileTransferFailed,
                        description: format!("[{}] Failed to finish gz stream encoding, got '{:?}'. The file will not be created", self.metrics.get_current_generation(), finish_err)
                    });
                }
            };
        } else {
            write_result = call_current_file_sharing_mode!(
                self.file_sharing,
                try_flush_events_to_file,
                file_path,
                file_content
            )
        }

        return write_result.map(|res| {
            self.metrics.add_file_sent_size(compressed_size);
            debug!(
                "[{}] Successfully wrote file '{}' using {:?} mode ({} bytes - initially {} bytes)",
                self.metrics.get_current_generation(),
                res,
                self.current_mode,
                compressed_size,
                initial_size
            );
        });
    }

    fn get_desired_file_sharing_mode_from_config(
        configuration: &EventsLogsConfiguration,
    ) -> FileSharingMode {
        match configuration.smb_mode_activated {
            true => FileSharingMode::SMB,
            false => FileSharingMode::SYSVOL,
        }
    }

    /// The file sharing manager will react to configuration changes
    /// However, he is only interested in "file sharing" changes so he will target a particular subset of properties
    pub fn on_configuration_change(
        &mut self,
        is_pdc: bool,
        updated_configuration: &EventsLogsConfiguration,
    ) -> Result<(), FileSharingError> {
        let desired_configuration_mode =
            Self::get_desired_file_sharing_mode_from_config(updated_configuration);

        if self.current_mode != desired_configuration_mode {
            info!(
                "Detected file sharing mode update, switching from {0:?} to {1:?}",
                self.current_mode, desired_configuration_mode
            );
            // We'll make sure to indicate to the previous implementation that the mode was switched
            call_current_file_sharing_mode!(self.file_sharing, disable)?;
            self.current_mode = desired_configuration_mode;
            self.file_sharing = create_file_sharing_mode!(
                self.current_mode,
                &self.original_args,
                &updated_configuration
            );
            call_current_file_sharing_mode!(self.file_sharing, set_is_pdc, is_pdc);
            call_current_file_sharing_mode!(self.file_sharing, setup)?;
            self.metrics.reset_files_sent();
        } else {
            call_current_file_sharing_mode!(
                self.file_sharing,
                on_configuration_change,
                &updated_configuration
            );
        }

        Ok(())
    }

    pub fn dump_metrics(&self) {
        info!(
            "Currently in '{:?}' mode, dumping metrics: {}",
            self.current_mode, self.metrics
        );
    }
}

impl Drop for FileSharingManager {
    fn drop(&mut self) {
        let _ = call_current_file_sharing_mode!(self.file_sharing, disable); // Swallowed error
    }
}

#[cfg(test)]
mod tests {
    mod on_configuration_change_support {
        use super::super::*;
        use crate::setup::init_test_logger;
        use crate::sharing::errors::FileSharingFailureReason::FileTransferFailed;
        use crate::EMPTY_STRING;
        use std::path::Path;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;
        use std::{fs, thread};
        use uuid::Uuid;

        #[test]
        fn it_should_disable_previous_mode_when_mode_changes() {
            init_test_logger();
            // Arrange
            let mut fake_mode = MockFileSharing::default();
            fake_mode.expect_disable().once().returning(|| Ok(()));
            let mut manager = FileSharingManager {
                current_mode: FileSharingMode::SMB,
                original_args: Arguments::default(),
                file_sharing: FileSharingImplementation::MockFileSharing(fake_mode),
                metrics: FileSharingMetrics::default(),
            };

            // Act && Asserts
            let _ = manager.on_configuration_change(true, &EventsLogsConfiguration::default());
        }

        /// This test reproduces the actual setup that we use in our main.rs
        #[test]
        fn it_should_be_able_to_detect_trigger_change_on_another_thread() {
            init_test_logger();
            // Arrange
            let file_path = format!("{}.test", Uuid::new_v4().to_string());
            let cloned_file_path = file_path.clone();
            let mut fake_mode = MockFileSharing::default();
            // The current mode will always fail. This is our indication that if we have a new mode set, we'll see no failure or a different one
            fake_mode
                .expect_try_flush_events_to_file()
                .returning(|_, _| {
                    Err(FileSharingError {
                        error: FileTransferFailed,
                        description: EMPTY_STRING.to_string(),
                    })
                });
            fake_mode.expect_disable().once().returning(|| Ok(()));
            let manager = Arc::new(Mutex::new(FileSharingManager {
                current_mode: FileSharingMode::SMB,
                original_args: Arguments::default(),
                file_sharing: FileSharingImplementation::MockFileSharing(fake_mode),
                metrics: FileSharingMetrics::default(),
            }));

            // Act
            // We will simulate a switch from the "Dedicated SMB share" mode to SYSVOL
            let share_thread_a = Arc::clone(&manager);
            let thread_a = thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(1));
                let send_file = share_thread_a.lock().unwrap().send_file(
                    &true,
                    &cloned_file_path,
                    &vec![42, 69],
                );
                if send_file.is_ok() {
                    break;
                }
            });
            let thread_b = thread::spawn(move || {
                let mut count = 0;
                loop {
                    if count == 3 {
                        let new_config =
                            EventsLogsConfiguration::default().with_smb_mode_activated(false);
                        manager
                            .lock()
                            .unwrap()
                            .on_configuration_change(true, &new_config)
                            .unwrap();
                        break;
                    }
                    thread::sleep(Duration::from_secs(1));
                    count += 1;
                }
            });

            // Asserts
            thread_a.join().unwrap();
            thread_b.join().unwrap();
            // We know only the SYSVOL implementation will create the file
            assert_eq!(true, Path::new(file_path.clone().as_str()).exists());
            fs::remove_file(file_path.as_str()).unwrap();
        }
    }

    mod on_send_file {
        use super::super::*;
        use crate::setup::init_test_logger;
        use crate::EMPTY_STRING;
        use chrono::Local;
        use flate2::read::GzDecoder;
        use std::io::Read;

        #[test]
        fn it_should_not_attempt_to_send_an_empty_file_content() {
            init_test_logger();
            // Arrange
            let mut fake_mode = MockFileSharing::default();
            fake_mode.expect_disable().once().returning(|| Ok(()));
            fake_mode
                .expect_try_flush_events_to_file()
                .never()
                .returning(|_, _| Ok("".into()));
            let mut manager = FileSharingManager {
                current_mode: FileSharingMode::SMB,
                original_args: Arguments::default(),
                file_sharing: FileSharingImplementation::MockFileSharing(fake_mode),
                metrics: FileSharingMetrics::default(),
            };

            // Act
            let write_result = manager.send_file(&true, &String::from(EMPTY_STRING), &Vec::new());

            // Assert
            assert_eq!(Ok(()), write_result);
        }

        #[test]
        fn it_should_compress_the_file_content_correctly() {
            init_test_logger();
            // Arrange
            let content = "Hello world ! This is a test";
            let mut fake_mode = MockFileSharing::default();
            fake_mode.expect_disable().once().returning(|| Ok(()));
            fake_mode
                .expect_try_flush_events_to_file()
                .withf(move |_, file_content: &Vec<u8>| {
                    let mut reader = GzDecoder::new(file_content.as_slice());
                    let mut uncompressed_content = String::new();
                    reader.read_to_string(&mut uncompressed_content).unwrap();
                    return uncompressed_content == content;
                })
                .once()
                .returning(|_, _| Ok("".to_string()));
            let mut manager = FileSharingManager {
                current_mode: FileSharingMode::SMB,
                original_args: Arguments::default(),
                file_sharing: FileSharingImplementation::MockFileSharing(fake_mode),
                metrics: FileSharingMetrics::default(),
            };

            // Act
            let write_result = manager.send_file(
                &true,
                &String::from(EMPTY_STRING),
                &content.clone().as_bytes().to_vec(),
            );

            // Assert
            assert_eq!(Ok(()), write_result);
        }

        #[test]
        fn it_should_not_compress_the_file_content_if_gzip_is_disabled() {
            init_test_logger();
            // Arrange
            let content = "456".as_bytes().to_vec();
            let mut fake_mode = MockFileSharing::default();
            fake_mode.expect_disable().once().returning(|| Ok(()));
            fake_mode
                .expect_try_flush_events_to_file()
                .withf(|_, file_content: &Vec<u8>| *file_content == "456".as_bytes().to_vec())
                .once()
                .returning(|_, _| Ok("test.gz".to_string()));
            let mut manager = FileSharingManager {
                current_mode: FileSharingMode::SMB,
                original_args: Arguments::default(),
                file_sharing: FileSharingImplementation::MockFileSharing(fake_mode),
                metrics: FileSharingMetrics::default(),
            };

            let enable_gzip = false;

            // Act
            let write_result =
                manager.send_file(&enable_gzip, &String::from(EMPTY_STRING), &content);

            // Assert
            assert_eq!(Ok(()), write_result);
        }

        #[test]
        fn it_should_add_metadata_into_gzip_headers_archive() {
            init_test_logger();
            // Arrange
            let file_generation = 42069;
            let content = "Hello world !";

            let mut fake_mode = MockFileSharing::default();
            fake_mode.expect_disable().once().returning(|| Ok(()));
            fake_mode
                .expect_try_flush_events_to_file()
                .withf(move |_, file_content: &Vec<u8>| {
                    let mut reader = GzDecoder::new(file_content.as_slice());
                    let header = reader.header().unwrap();
                    let comment = String::from_utf8(header.comment().unwrap().to_vec()).unwrap();
                    let extra_info =
                        u64::from_be_bytes(header.extra().unwrap().try_into().unwrap());
                    let created_at = header.mtime_as_datetime().unwrap();
                    let mut uncompressed_content = String::new();
                    reader.read_to_string(&mut uncompressed_content).unwrap();
                    // Ensure all metadata was properly added to the GZ archive headers + verify content is as expected
                    return comment == env!("CARGO_PKG_VERSION")
                            && extra_info == file_generation + 1 // As soon as we enter the send function, the generation is always incremented
                            && uncompressed_content == content
                            && chrono::DateTime::<Local>::from(created_at).date() == Local::today();
                })
                .once()
                .returning(|_, _| Ok("".to_string()));

            let mut metrics = FileSharingMetrics::default();
            for _ in 0..file_generation {
                metrics.increment_file_generation();
            }
            let mut manager = FileSharingManager {
                current_mode: FileSharingMode::SMB,
                original_args: Arguments::default(),
                file_sharing: FileSharingImplementation::MockFileSharing(fake_mode),
                metrics: metrics,
            };

            // Act
            let write_result = manager.send_file(
                &true,
                &String::from(EMPTY_STRING),
                &content.clone().as_bytes().to_vec(),
            );

            // Assert
            assert_eq!(Ok(()), write_result);
        }
    }

    mod on_disable {
        use super::super::*;
        use crate::setup::init_test_logger;

        #[test]
        fn it_should_disable_current_mode_on_drop() {
            init_test_logger();
            // Arrange
            let mut fake_mode = MockFileSharing::default();
            fake_mode.expect_disable().once().returning(|| Ok(()));
            let manager = FileSharingManager {
                current_mode: FileSharingMode::SMB,
                original_args: Arguments::default(),
                file_sharing: FileSharingImplementation::MockFileSharing(fake_mode),
                metrics: FileSharingMetrics::default(),
            };

            // Act && Asserts
            // Force dropping the file sharing manager should call the disable function of the current mode
            drop(manager);
        }
    }
}
