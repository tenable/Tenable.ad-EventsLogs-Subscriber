use std::env::current_dir;
use std::fs;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use log::info;
use windows::Win32::Storage::FileSystem;
use crate::configuration::{Arguments, EventsLogsConfiguration};
use crate::sharing::errors::{FileSharingError};
use crate::sharing::errors::FileSharingFailureReason::FileTransferFailed;
use crate::sharing::file_sharing::FileSharing;

pub struct SysvolFileSharing {
    enabled: bool,
    event_logs_directory: PathBuf,
    is_pdc: bool,
}

impl FileSharing for SysvolFileSharing {
    fn new(args: &Arguments, _: &EventsLogsConfiguration) -> Self {
        Self {
            enabled: false,
            is_pdc: false,
            event_logs_directory: Path::new(&args.event_log_file_path).parent()
                .unwrap_or(current_dir().unwrap().as_path()) // Default out of safety
                .to_owned()
        }
    }

    fn set_is_pdc(&mut self, _: bool) {
        self.is_pdc = true;
    }

    /// SYSVOL has no specific setup actions
    fn setup(&mut self) -> Result<(), FileSharingError> {
        assert!(!self.enabled, "setup() function should not be called twice in a normal workflow");
        self.enabled = true;
        info!("SYSVOL file sharing is enabled !");
        Ok(())
    }

    /// SYSVOL has nothing particular to do when disabling itself
    /// We simply :
    ///     - Stop writing there
    ///     - For convenience, delete *.gz files available there in order to avoid leaving future stall files
    fn disable(&mut self) -> Result<(), FileSharingError> {
        for path in fs::read_dir(self.event_logs_directory.clone()).unwrap() {
            let path = path.unwrap().path();
            match path.extension() {
                Some(extension) => {
                    if extension == "gz" {
                        let _ = fs::remove_file(&path);
                        info!("Deleted {:?} produced event logs file", path.as_os_str())
                    }
                }
                None => {}
            }
        }

        self.enabled = false;
        info!("SYSVOL file sharing usage is disabled");
        Ok(())
    }

    fn try_flush_events_to_file(&mut self, file_path: &String, file_content: &Vec<u8>) -> Result<String, FileSharingError> {
        assert!(self.enabled, "This should never happen. Make sure you properly called 'setup()' before trying to send some files");
        let sharing_mode = FileSystem::FILE_SHARE_READ | FileSystem::FILE_SHARE_WRITE;
        let events_file_open = fs::File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .share_mode(sharing_mode.0)
            .open(file_path);

        let mut events_file = match events_file_open {
            Ok(f) => f,
            Err(file_open_err) => {
                return Err(FileSharingError {
                    error: FileTransferFailed,
                    description: format!("SYSVOL mode was not able to open file at '{}' for writing, got '{:?}'", file_path, file_open_err),
                })
            },
        };

        return match events_file.write_all(&file_content) {
            Ok(_) => Ok(file_path.clone()),
            Err(file_write_err) => Err(FileSharingError {
                error: FileTransferFailed,
                description: format!("SYSVOL mode was not able to write in file '{}', got '{:?}'", file_path, file_write_err),
            })
        };
    }

    fn on_configuration_change(&mut self, _: &EventsLogsConfiguration) {}
}

#[cfg(test)]
mod tests {
    mod sysvol_file_creation {
        use std::fs::File;
        use tempfile::TempDir;
        use super::super::*;

        #[test]
        fn it_should_not_allow_to_send_file_if_setup_not_called_before() {
            // Arrange
            std::panic::set_hook(Box::new(|_| { })); // Suppress console output for panic
            let mut sysvol = SysvolFileSharing::new(&Arguments::default(), &EventsLogsConfiguration::default());

            // Act && Asserts
            let send_file = std::panic::catch_unwind(move || sysvol.try_flush_events_to_file(&"fake_path".to_string(), &Vec::new()));

            // Asserts
            assert!(send_file.is_err());
        }

        #[test]
        fn it_should_create_the_file_if_it_does_not_exist() {
            // Arrange
            let mut sysvol = SysvolFileSharing::new(&Arguments::default(), &EventsLogsConfiguration::default());
            let _ = sysvol.setup();

            let tmp_dir = TempDir::new().unwrap();
            let tmp_dir_path = tmp_dir.path().to_str().unwrap();
            let tmp_file_path = format!("{tmp_dir_path}/out");

            let content = "Test".as_bytes().to_vec();

            // Act
            let write_result = sysvol.try_flush_events_to_file(&tmp_file_path, &content);

            // Assert
            assert!(write_result.is_ok());
            let result = fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("Test", result);
        }

        #[test]
        fn it_should_overwrite_the_file_content() {
            // Arrange
            let mut sysvol = SysvolFileSharing::new(&Arguments::default(), &EventsLogsConfiguration::default());
            let _ = sysvol.setup();

            let (_tmp_dir, tmp_file_path) = get_tmp_file_path("123");

            let content = "456".as_bytes().to_vec();

            let result = fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("123", result);

            // Act
            let write_result = sysvol.try_flush_events_to_file(&tmp_file_path, &content);

            // Assert
            assert!(write_result.is_ok());
            let result = fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("456", result);
        }

        #[test]
        fn it_should_not_work_if_the_file_is_not_accessible() {
            // Arrange
            let mut sysvol = SysvolFileSharing::new(&Arguments::default(), &EventsLogsConfiguration::default());
            let _ = sysvol.setup();

            let (_tmp_dir, tmp_file_path) = get_tmp_file_path("123");

            let content = "456".as_bytes().to_vec();

            let result = fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("123", result);

            let sharing_mode = FileSystem::FILE_SHARE_NONE;
            let file = File::options()
                .create(true)
                .read(true)
                .write(true)
                .share_mode(sharing_mode.0)
                .open(&tmp_file_path);

            // Act
            let write_result = sysvol.try_flush_events_to_file(&tmp_file_path, &content);

            // Assert
            drop(file);
            assert!(write_result.is_err());
            let result = fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("123", result);
        }

        fn get_tmp_file_path(content: &str) -> (TempDir, String) {
            let tmp_dir = TempDir::new().unwrap();
            let tmp_dir_path = tmp_dir.path().to_str().unwrap();
            let tmp_file_path = format!("{tmp_dir_path}/out");

            let mut file = File::create(&tmp_file_path).unwrap();
            file.write_all(content.as_bytes()).unwrap();

            (tmp_dir, tmp_file_path)
        }
    }

    mod sysvol_disable {
        use tempfile::TempDir;
        use super::super::*;

        #[test]
        fn it_should_delete_all_gz_files_on_disable() {
            // Arrange
            let tmp_dir = TempDir::new().unwrap();
            let content = "Test".as_bytes().to_vec();
            let tmp_dir_path = tmp_dir.path().to_str().unwrap();
            let tmp_file_path = format!("{tmp_dir_path}/out.test");
            let tmp_gz_file_path = format!("{tmp_dir_path}/eventlog.gz");
            let mut args = Arguments::default();
            args.event_log_file_path = tmp_gz_file_path.clone();
            let mut sysvol = SysvolFileSharing::new(&args, &EventsLogsConfiguration::default());
            let _ = sysvol.setup();

            // Act
            let _ = sysvol.try_flush_events_to_file(&tmp_file_path, &content.clone());
            let _ = sysvol.try_flush_events_to_file(&tmp_gz_file_path, &content);
            let disable = sysvol.disable();

            // Asserts
            assert_eq!(Ok(()), disable);
            // The gz file should have been deleted, not the other
            assert_eq!(false, Path::new(&tmp_gz_file_path).exists());
            assert_eq!(true, Path::new(&tmp_file_path).exists());
        }
    }
}