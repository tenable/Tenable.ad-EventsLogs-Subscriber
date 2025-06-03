use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use log::{error, info, warn};
use remotefs::RemoteFs;
use crate::helpers::{get_pdce_hostname, sanitize_for_powershell};
use crate::sharing::errors::{FileSharingError, FileSharingFailureReason};
use crate::sharing::file_sharing::FileSharing;
use crate::sharing::smb::windows::*;
use crate::configuration::{Arguments, EventsLogsConfiguration};
use remotefs_smb::{SmbCredentials, SmbFs};
use crate::EMPTY_STRING;
use crate::sharing::errors::FileSharingFailureReason::DisableError;

/// Name of the SMB share accessed by all clients
const SMB_SHARE_NAME: &str = "TIE-IOA-Logs$";
/// Comment linked to SMB share.
///
/// It will appear on mouse hover on the share name in the Network tab on Windows
const SMB_REMARK: &str = "Tenable IOA event files share";

pub struct SmbFileSharing {
    is_pdc: bool,
    pdce_hostname: String,
    smb_share_location: String,
    current_relay_account: String,
    pub(super) smb_client: Option<SmbFs>,
    #[cfg(not(test))]
    smb_platform_specific_actions: WindowsSmbPlatformSpecificActions,
    #[cfg(test)]
    smb_platform_specific_actions: MockSmbPlatformSpecificActions,
}

impl FileSharing for SmbFileSharing {
    fn new(args: &Arguments, configuration: &EventsLogsConfiguration) -> Self {
        Self {
            is_pdc: false,
            pdce_hostname: get_pdce_hostname(),
            current_relay_account: sanitize_for_powershell(&configuration.relay_account_username),
            // This eliminates potential escaping problems that could be forwarded to this parameter
            smb_share_location: args.smb_share_location.clone().replace("\\\\", "\\"),
            smb_client: None,
            #[cfg(not(test))]
            smb_platform_specific_actions: WindowsSmbPlatformSpecificActions::default(),
            #[cfg(test)]
            smb_platform_specific_actions: MockSmbPlatformSpecificActions::default(),
        }
    }

    fn set_is_pdc(&mut self, is_pdc: bool) { self.is_pdc = is_pdc; }

    fn setup(&mut self) -> Result<(), FileSharingError> {
        assert!(self.smb_client.is_none(), "setup() function should not be called twice in a normal workflow");
        assert!(!self.smb_share_location.is_empty(), "A default SMB share physical location must be supplied");

        // Without SMB enabled, we cannot do anything so let's stop right here in that case
        if !self.smb_platform_specific_actions.is_smb_enabled() {
            return Err(FileSharingError {
                error: FileSharingFailureReason::MandatoryPrerequisitesNotFilled,
                description: "SMB is not enabled on your machine".into(),
            })
        }

        if self.is_pdc {
            let path = Path::new(&self.smb_share_location);
            if !path.is_absolute() {
                return Err(FileSharingError {
                    error: FileSharingFailureReason::MandatoryPrerequisitesNotFilled,
                    description: format!("Path '{}' is not an absolute path", self.smb_share_location),
                })
            }
            // Create the SMB default physical directory if it doesn't exist
            match path.try_exists() {
                Ok(exists) => {
                    if exists {
                        info!("SMB physical folder '{}' already exists", self.smb_share_location);
                    } else {
                        fs::create_dir_all(&self.smb_share_location).map_err(|err| FileSharingError {
                            error: FileSharingFailureReason::MandatoryPrerequisitesNotFilled,
                            description: format!("Couldn't create physical directory for SMB share at '{}', got '{}'", self.smb_share_location, err.to_string()),
                        })?;
                        info!("Created folder needed for SMB share at '{}'", self.smb_share_location);
                    }
                },
                Err(err_not_exists) => {
                    if err_not_exists.kind() == ErrorKind::NotFound {
                        info!("Couldn't find '{}' folder needed for SMB share, will create it ...", self.smb_share_location);
                        fs::create_dir_all(&self.smb_share_location).map_err(|err| FileSharingError {
                            error: FileSharingFailureReason::MandatoryPrerequisitesNotFilled,
                            description: format!("Couldn't create physical directory for SMB share at '{}', got '{}'", self.smb_share_location, err.to_string()),
                        })?;
                        info!("Created folder needed for SMB share at '{}'", self.smb_share_location);
                    }
                }
            }

            assert_eq!(path.exists(), true, "The SMB physical folder should have been created at this point");

            // We always (re)configure the share to ensure the proper access rights are set
            match self.smb_platform_specific_actions.secure_smb_folder_access(&self.smb_share_location, &self.current_relay_account) {
                Ok(()) => info!("SMB physical folder access at '{}' has been properly secured !", self.smb_share_location),
                Err(smb_hardening_err) => {
                    // Try to delete the physical folder also
                    let _ = fs::remove_dir_all(path);
                    return Err(smb_hardening_err)
                }
            };

            self.smb_platform_specific_actions.create_smb_share(
                &self.pdce_hostname,
                SMB_SHARE_NAME,
                &self.smb_share_location,
                SMB_REMARK,
            ).map_err(|create_err| {
                // Leave a clean state if we couldn't create the SMB share by deleting physical folder
                let _ = fs::remove_dir_all(path);
                return create_err;
            })?;

            match self.smb_platform_specific_actions.secure_smb_share_access(SMB_SHARE_NAME, &self.current_relay_account) {
                Ok(()) => info!("SMB share access has been properly secured !"),
                Err(smb_hardening_err) => {
                    // We let the error flow up back to the caller, but we'll handle the clean the share as it's unsecure at the moment and other DC could start sending data there
                    let _ = self.smb_platform_specific_actions.delete_smb_share(&self.pdce_hostname, SMB_SHARE_NAME)
                        // That's an emergency situation that should not happen.
                        // Nonetheless, it is important to warn that we were unable to do it automatically
                        .map_err(|_| error!("Unable to secure nor delete the {} SMB share. Please delete it manually and retry", SMB_SHARE_NAME));
                    // Try to delete the physical folder also
                    let _ = fs::remove_dir_all(path);
                    return Err(smb_hardening_err)
                }
            };
        } else {
            info!("Current computer is not PDCe, skipping SMB setup");
        }

        self.smb_client = Some(SmbFs::new(
            SmbCredentials::new(self.pdce_hostname.as_str(), SMB_SHARE_NAME)
        ));

        return match self.connect_to_smb() {
            Ok(()) => {
                info!("File sharing setup completed successfully");
                Ok(())
            }
            Err(connect_err) => {
                // Let's not block non-PDCe machines from completing the setup step if we cannot connect to the SMB share
                // We will let normal DCs "escape" this function to enter the main processing loop
                // The connection loop will retry connecting every time anyway
                if !self.is_pdc {
                    warn!("Client couldn't connect to the SMB share. Will retry connecting on each events file sent");
                    return Ok(());
                }
                Err(connect_err)
            }
        }
    }

    fn disable(&mut self) -> Result<(), FileSharingError> {
        self.disconnect_from_smb()?;

        if self.is_pdc {
            let ask_smb_physical_folder_location = self.smb_platform_specific_actions.get_smb_share_physical_location(SMB_SHARE_NAME);
            self.smb_platform_specific_actions.delete_smb_share(&self.pdce_hostname, SMB_SHARE_NAME)?;
            let smb_physical_folder = ask_smb_physical_folder_location.unwrap_or_else(|| EMPTY_STRING.to_string());

            // This location can be trusted 100% as it's the one currently in use when disabling the share
            if !smb_physical_folder.is_empty() {
                // Delete the physical directory of the SMB share and its content
                fs::remove_dir_all(&smb_physical_folder).map_err(|delete_err| FileSharingError {
                    error: DisableError,
                    description: format!("Couldn't delete actual smb physical folder at '{}' got '{}'", smb_physical_folder, delete_err.to_string()),
                })?;
                info!("Deleted actual folder for SMB share at '{}'", self.smb_share_location);
            }

            // Out of safety, we'll delete the smb_share_location passed in parameter (even if it's probably already deleted)
            if !self.smb_share_location.is_empty() && smb_physical_folder != self.smb_share_location {
                fs::remove_dir_all(&self.smb_share_location).map_err(|delete_err| FileSharingError {
                    error: DisableError,
                    description: format!("Couldn't delete smb physical folder at '{}' got '{}'", self.smb_share_location, delete_err.to_string()),
                })?;
                info!("Deleted folder for SMB share at '{}'", self.smb_share_location);
            }
        } else {
            info!("Current computer is not PDCe, skipping SMB deletion steps");
        }

        self.smb_client = None;
        info!("SMB file sharing has been disabled !");
        Ok(())
    }

    fn try_flush_events_to_file(&mut self, file_path: &String, file_content: &Vec<u8>) -> Result<String, FileSharingError> {
        assert!(self.smb_client.is_some(), "This should never happen. Make sure you properly called 'setup()' before trying to send some files");

        // We will reconnect the client silently if we are somehow not/(dis)connected
        if !self.smb_client.as_mut().unwrap().is_connected() {
            info!("Currently not connected to SMB share, will attempt reconnection now...");
            self.connect_to_smb()?;
        }

        // Send the actual file content
        // Extract only the filename in the case of SMB as the client already has the full path waiting for us
        let filename = Path::new(Path::new(file_path).file_name().unwrap());
        self.send_file(filename, file_content)?;
        let written_to = Path::new("\\\\")
            .join(&self.pdce_hostname)
            .join(SMB_SHARE_NAME)
            .join(filename);

        return Ok(written_to.to_str().unwrap().to_string());
    }

    /// The "Dedicated SMB share" mode reacts to potential configuration changes
    /// The only interesting changes are:
    ///     - A change in the Relay service account used
    fn on_configuration_change(&mut self, updated_configuration: &EventsLogsConfiguration) {
        if self.current_relay_account != updated_configuration.relay_account_username {
            self.current_relay_account = sanitize_for_powershell(&updated_configuration.relay_account_username);
            info!("Updating SMB share access rights for new relay service account '{}'", self.current_relay_account);
            let _ = self.smb_platform_specific_actions.secure_smb_folder_access(&self.smb_share_location, &self.current_relay_account);
            let _ = self.smb_platform_specific_actions.secure_smb_share_access(SMB_SHARE_NAME, &self.current_relay_account);
        } else {
            info!("No significant change detected to configuration for the 'Dedicated SMB share' mode");
        }
    }
}

#[cfg(test)]
mod tests {
    mod smb_setup {
        use super::super::*;
        use crate::EMPTY_STRING;

        #[test]
        fn it_should_skip_creation_of_smb_share_when_not_pdce() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_create_smb_share().never();
            platform_mock.expect_is_smb_enabled().once().return_const(true);
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: platform_mock
            };

            // Act && Asserts
            let _ = smb.setup();
        }

        /// This is testing an "impossible" code path but better be safe than sorry
        #[test]
        fn it_should_panic_on_empty_smb_share_location() {
            // Arrange
            std::panic::set_hook(Box::new(|_| { })); // Suppress console output for panic
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: EMPTY_STRING.to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: MockSmbPlatformSpecificActions::default(),
            };

            // Act && Asserts
            let setup = std::panic::catch_unwind(move || smb.setup());

            // Asserts
            assert!(setup.is_err());
        }

        #[test]
        fn it_should_return_error_on_smb_disabled_detected() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_create_smb_share().never();
            platform_mock.expect_is_smb_enabled().once().return_const(false);
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: platform_mock
            };

            // Act
            let setup_err = smb.setup();

            // Asserts
            assert!(setup_err.is_err());
        }

        #[test]
        fn it_should_return_error_on_non_absolute_path_for_smb_share() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_create_smb_share().never();
            platform_mock.expect_is_smb_enabled().once().return_const(true);
            let mut smb = SmbFileSharing {
                is_pdc: true,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "test".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: platform_mock
            };

            // Act
            let setup_err = smb.setup();

            // Asserts
            assert!(setup_err.is_err());
        }

        #[test]
        fn it_should_create_a_smb_share_when_pdce() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_is_smb_enabled().once().return_const(true);
            platform_mock.expect_create_smb_share()
                .withf(
                    |pdce_hostname: &String, share_name: &str, physical_location: &String, _| {
                        *pdce_hostname == String::from("test") && *share_name == *SMB_SHARE_NAME && *physical_location == String::from("C:\\Tenable\\TestLocation")
                    }
                )
                .once()
                .returning(|_, _, _, _| Ok(()));
            platform_mock.expect_secure_smb_share_access().once().returning(|_, _| Ok(()));
            platform_mock.expect_secure_smb_folder_access().once().returning(|_, _| Ok(()));

            let mut smb = SmbFileSharing {
                is_pdc: true,
                pdce_hostname: String::from("test"),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: platform_mock
            };

            // Act && Asserts
            let _ = smb.setup();
        }

        #[test]
        fn it_should_return_an_error_if_smb_physical_folder_cannot_be_secured_when_pdce() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_is_smb_enabled().once().return_const(true);
            // We never create the SMB share if the physical folder cannot be secured first
            platform_mock.expect_create_smb_share().never();
            platform_mock.expect_secure_smb_share_access().never();
            platform_mock.expect_secure_smb_folder_access().once().returning(|_, _| Err(FileSharingError {
                error: FileSharingFailureReason::SetupError,
                description: "test error".to_string(),
            }));

            let mut smb = SmbFileSharing {
                is_pdc: true,
                pdce_hostname: String::from("test"),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: platform_mock
            };

            // Act && Asserts
            let smb_setup = smb.setup();
            assert!(smb_setup.is_err());
            let setup_error = smb_setup.unwrap_err();
            assert_eq!(setup_error.error, FileSharingFailureReason::SetupError);
            assert_eq!(setup_error.description, "test error".to_string());
        }

        #[test]
        fn it_should_return_an_error_if_smb_share_cannot_be_secured_when_pdce() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_is_smb_enabled().once().return_const(true);
            platform_mock.expect_create_smb_share()
                .once()
                .returning(|_, _, _, _| Ok(()));
            // We must make sure that in the event of a configuration error, we leave a clean environment
            platform_mock.expect_delete_smb_share().once().returning(|_, _| Ok(()));
            platform_mock.expect_secure_smb_share_access().once().returning(|_, _| Err(FileSharingError {
                error: FileSharingFailureReason::SetupError,
                description: "test error".to_string(),
            }));
            platform_mock.expect_secure_smb_folder_access().once().returning(|_, _| Ok(()));

            let mut smb = SmbFileSharing {
                is_pdc: true,
                pdce_hostname: String::from("test"),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: platform_mock
            };

            // Act && Asserts
            let smb_setup = smb.setup();
            assert!(smb_setup.is_err());
            let setup_error = smb_setup.unwrap_err();
            assert_eq!(setup_error.error, FileSharingFailureReason::SetupError);
            assert_eq!(setup_error.description, "test error".to_string());
        }
    }

    mod smb_disable {
        use tempfile::TempDir;
        use super::super::*;
        use crate::EMPTY_STRING;

        #[test]
        fn it_should_delete_smb_share_when_pdce() {
            // Arrange
            let tempDir = TempDir::new().unwrap();
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_get_smb_share_physical_location().once().return_const(EMPTY_STRING.to_string());
            platform_mock.expect_delete_smb_share().once().returning(|_, _| Ok(()));
            let mut smb = SmbFileSharing {
                is_pdc: true,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: tempDir.path().as_os_str().to_string_lossy().to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: Some(SmbFs::new(Default::default())),
                smb_platform_specific_actions: platform_mock
            };

            // Act
            let disable = smb.disable();

            // Asserts
            assert_eq!(Ok(()), disable);
        }

        #[test]
        fn it_should_delete_smb_physical_location_directory_when_pdce() {
            // Arrange
            let fake_dir_location = TempDir::new().unwrap();
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_get_smb_share_physical_location().once().return_const(EMPTY_STRING.to_string());
            platform_mock.expect_delete_smb_share().once().returning(|_, _| Ok(()));
            let mut smb = SmbFileSharing {
                is_pdc: true,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: fake_dir_location.path().as_os_str().to_string_lossy().to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: Some(SmbFs::new(Default::default())),
                smb_platform_specific_actions: platform_mock
            };

            // Act
            let disable_smb = smb.disable();

            assert_eq!(Ok(()), disable_smb);
            assert!(!fake_dir_location.path().exists());
        }

        #[test]
        fn it_should_also_delete_smb_actual_directory_when_pdce() {
            // Arrange
            let fake_dir_location = TempDir::new().unwrap();
            let previous_smb_location = TempDir::new().unwrap();
            let prev_smb_folder = previous_smb_location.path().as_os_str().to_string_lossy().to_string();
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_get_smb_share_physical_location().once().return_const(prev_smb_folder.clone());
            platform_mock.expect_delete_smb_share().once().returning(|_, _| Ok(()));
            let mut smb = SmbFileSharing {
                is_pdc: true,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: fake_dir_location.path().as_os_str().to_string_lossy().to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: Some(SmbFs::new(Default::default())),
                smb_platform_specific_actions: platform_mock
            };

            // Act
            let disable_smb = smb.disable();

            assert_eq!(Ok(()), disable_smb);
            assert!(!fake_dir_location.path().exists());
            // The previous location should also have been deleted, just in case
            assert!(!previous_smb_location.path().exists());
        }

        #[test]
        fn it_should_not_try_to_delete_smb_share_when_not_pdce() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_get_smb_share_physical_location().never();
            platform_mock.expect_delete_smb_share().never();
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: Some(SmbFs::new(Default::default())),
                smb_platform_specific_actions: platform_mock
            };

            // Act
            let disable = smb.disable();

            // Asserts
            assert_eq!(Ok(()), disable);
        }

        #[cfg(feature = "test-with-containers")]
        #[test]
        fn it_should_drop_smb_client_when_calling_disable() {
            // Arrange
            let host = "localhost".to_string();

            let mut smb_client = SmbFs::new(
                SmbCredentials::new(host, SMB_SHARE_NAME.to_string()),
            );
            assert!(smb_client.connect().is_ok());
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                smb_client: Some(smb_client),
                smb_platform_specific_actions: MockSmbPlatformSpecificActions::default(),
            };

            // Act
            let disabled = smb.disable();

            // Asserts
            assert!(disabled.is_ok());
            assert!(smb.smb_client.is_none());
        }
    }

    #[cfg(feature = "test-with-containers")]
    mod smb_send_file_integration {
        use super::super::*;
        use std::io::Read;
        use std::path::Path;
        use remotefs::RemoteFs;
        use uuid::Uuid;

        #[test]
        fn it_should_be_able_to_send_file_to_smb_share() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_is_smb_enabled().once().return_const(true);
            let host = "localhost".to_string();
            let file_path = String::from("write_test.txt");
            let content = format!("This is some test file content with {}", Uuid::new_v4().to_string());

            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: host.clone(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                smb_client: None,
                smb_platform_specific_actions: platform_mock,
            };
            assert!(smb.setup().is_ok());

            // Act
            let send_file = smb.try_flush_events_to_file(&file_path, &content.as_bytes().to_vec());

            // Asserts
            assert!(send_file.is_ok());
            // Read the file using our own smb client so we don't interfere with the one which is managed by the instance
            let mut smb_client = SmbFs::new(
                SmbCredentials::new(host, SMB_SHARE_NAME.to_string()),
            );
            assert!(smb_client.connect().is_ok());
            assert_eq!(content, read_smb_file_as_string(&mut smb_client, &file_path));
        }

        #[test]
        fn it_should_overwrite_the_file_content_on_file_already_exists() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_is_smb_enabled().once().return_const(true);
            let file_path = String::from("overwrite_test.txt");
            let original_content = format!("This is some test file content with {}", Uuid::new_v4().to_string());
            let new_content = format!("All new content is {}", Uuid::new_v4().to_string());

            let host = "localhost".to_string();
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: host.clone(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                smb_client: None,
                smb_platform_specific_actions: MockSmbPlatformSpecificActions::default(),
            };
            assert!(smb.setup().is_ok());

            // Act
            assert!(smb.try_flush_events_to_file(&file_path, &original_content.as_bytes().to_vec()).is_ok());
            let overwrite_file = smb.try_flush_events_to_file(&file_path, &new_content.as_bytes().to_vec());

            // Asserts
            assert!(overwrite_file.is_ok());
            // Read the file using our own smb client so we don't interfere with the one which is managed by the instance
            let mut smb_client = SmbFs::new(
                SmbCredentials::new(host, SMB_SHARE_NAME.to_string()),
            );
            assert!(smb_client.connect().is_ok());
            assert_eq!(new_content, read_smb_file_as_string(&mut smb_client, &file_path));
        }

        fn read_smb_file_as_string(smb_client: &mut SmbFs, path: &String) -> String {
            let read_operation = smb_client.open(Path::new(&path));
            assert!(read_operation.is_ok());

            let mut read_buffer = Vec::new();
            read_operation.unwrap().read_to_end(&mut read_buffer).expect("could not read file on smb");
            return String::from_utf8(read_buffer).unwrap();
        }
    }

    mod smb_send_file {
        use super::super::*;
        use crate::EMPTY_STRING;

        #[test]
        fn it_should_not_allow_to_call_send_file_if_setup_was_not_called_before() {
            // Arrange
            std::panic::set_hook(Box::new(|_| { })); // Suppress console output for panic
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: None,
                smb_platform_specific_actions: MockSmbPlatformSpecificActions::default(),
            };

            // Act && Asserts
            let send_file = std::panic::catch_unwind(move || smb.try_flush_events_to_file(&String::from("fake_path"), &Vec::new()));

            // Asserts
            assert!(send_file.is_err());
        }
    }

    mod on_configuration_change {
        use remotefs_smb::SmbFs;
        use crate::configuration::EventsLogsConfiguration;
        use crate::EMPTY_STRING;
        use crate::sharing::file_sharing::FileSharing;
        use crate::sharing::smb::implementation::SmbFileSharing;
        use crate::sharing::smb::windows::MockSmbPlatformSpecificActions;

        #[test]
        fn it_should_not_do_anything_on_no_significant_configuration_change() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_secure_smb_folder_access().never();
            platform_mock.expect_secure_smb_share_access().never();
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: Some(SmbFs::new(Default::default())),
                smb_platform_specific_actions: platform_mock
            };

            // Act
            smb.on_configuration_change(&EventsLogsConfiguration::default());
        }

        #[test]
        fn it_should_re_configure_smb_access_rights_on_relay_account_change() {
            // Arrange
            let mut platform_mock = MockSmbPlatformSpecificActions::default();
            platform_mock.expect_secure_smb_folder_access().once()
                .withf(|_: &String, relay_account: &String| {
                    relay_account == "foobar"
                })
                .returning(|_, _| Ok(()));
            platform_mock.expect_secure_smb_share_access().once()
                .withf(|_: &str, relay_account: &String| {
                    relay_account == "foobar"
                })
                .returning(|_, _| Ok(()));
            let mut smb = SmbFileSharing {
                is_pdc: false,
                pdce_hostname: EMPTY_STRING.to_string(),
                smb_share_location: "C:\\Tenable\\TestLocation".to_string(),
                current_relay_account: EMPTY_STRING.to_string(),
                smb_client: Some(SmbFs::new(Default::default())),
                smb_platform_specific_actions: platform_mock
            };

            // Act
            smb.on_configuration_change(&EventsLogsConfiguration::default().with_relay_account_username("foobar"));
        }
    }
}