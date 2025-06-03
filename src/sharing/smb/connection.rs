use std::io::Cursor;
use std::path::Path;
use std::time::SystemTime;
use remotefs::RemoteFs;
use log::{info, warn};
use remotefs::fs::{FileType, Metadata, UnixPex};
use retry::delay::Fixed;
use retry::retry_with_index;
use windows::Win32::Foundation::ERROR_BAD_NET_NAME;
use crate::EMPTY_STRING;
use crate::sharing::errors::FileSharingError;
use crate::sharing::errors::FileSharingFailureReason::{ConnectionError, DisableError, FileTransferFailed};
use crate::sharing::smb::implementation::SmbFileSharing;

/// Delay in ms between each attempt while disconnecting
const SMB_DISCONNECT_RETRY_DELAY_MS: u64 = 500;
/// Number of attempts for the "SMB disconnect" operation
const SMB_DISCONNECT_NB_ATTEMPTS: usize = 3;
/// Delay in ms between each attempt while connecting
const SMB_CONNECT_RETRY_DELAY_MS: u64 = 1000;
/// Number of attempts for the "SMB connect" operation
const SMB_CONNECT_NB_ATTEMPTS: usize = 5;
/// Delay between each retry attempts when sending a file
const SMB_SEND_FILE_RETRY_DELAY_IN_MS: u64 = 500;
/// Maximum number of attempts when trying to send a file
const SMB_SEND_FILE_NB_ATTEMPTS: usize = 5;

/// Helpers related to SMB connection management
impl SmbFileSharing {
    pub(super) fn connect_to_smb(&mut self) -> Result<(), FileSharingError> {
        assert!(self.smb_client.is_some(), "The SMB client should be initiated before calling 'connect_to_smb()'. Please call 'setup()' before.");

        let smb_client_connect = retry_with_index(Fixed::from_millis(SMB_CONNECT_RETRY_DELAY_MS).take(SMB_CONNECT_NB_ATTEMPTS), |current_try| {
            match self.smb_client.as_mut().unwrap().connect() {
                Ok(_) => {
                    info!("SMB client connected !");
                    Ok(())
                },
                Err(connectErr) => {
                    warn!("Cannot connect client to SMB share, got '{:?} - {:?}' on attempt {} out of {}, will retry in {}ms",
                        connectErr.kind, connectErr.msg.unwrap_or(EMPTY_STRING.to_string()),
                        current_try - 1, SMB_CONNECT_NB_ATTEMPTS, SMB_CONNECT_RETRY_DELAY_MS);
                    Err(FileSharingError {
                        error: ConnectionError,
                        description: "Cannot connect to SMB share".to_string(),
                    })
                }
            }
        });

        return smb_client_connect.map_err(|e| e.error);
    }

    pub(super) fn disconnect_from_smb(&mut self) -> Result<(), FileSharingError> {
        if self.smb_client.is_none() {
            return Ok(());
        }

        if self.smb_client.as_mut().unwrap().is_connected() {
            let smb_client_disconnect = retry_with_index(Fixed::from_millis(SMB_DISCONNECT_RETRY_DELAY_MS).take(SMB_DISCONNECT_NB_ATTEMPTS), |current_try| {
                match self.smb_client.as_mut().unwrap().disconnect() {
                    Ok(_) => {
                        info!("Client disconnected from SMB share");
                        Ok(())
                    },
                    Err(err) => {
                        warn!("Cannot disconnect client from SMB share, got '{:?}' on attempt {} out of {}, will retry in {}ms",
                            err.kind, current_try - 1, SMB_DISCONNECT_NB_ATTEMPTS, SMB_DISCONNECT_RETRY_DELAY_MS);
                        Err(FileSharingError {
                            error: DisableError,
                            description: "Cannot disconnect from SMB share".to_string(),
                        })
                    }
                }
            });
            if let Err(retry_error) = smb_client_disconnect {
                return Err(retry_error.error);
            }
        } else {
            warn!("Attempted to disconnect an already disconnected SMB client. This operation will be skipped");
        }

        return Ok(());
    }

    pub(super) fn send_file(&mut self, path: &Path, file_content: &Vec<u8>) -> Result<(), FileSharingError> {
        let file_metadata = Metadata {
            accessed: None,
            created: Some(SystemTime::now()),
            gid: None,
            mode: Some(UnixPex::from(0o644)),
            modified: None,
            size: file_content.len() as u64,
            symlink: None,
            file_type: FileType::File,
            uid: None,
        };

        let mut suggest_disconnection = false;
        let create_file_result = retry_with_index(Fixed::from_millis(SMB_SEND_FILE_RETRY_DELAY_IN_MS).take(SMB_SEND_FILE_NB_ATTEMPTS), |current_try| {
            suggest_disconnection = false;
            match self.smb_client.as_mut().unwrap().create_file(path, &file_metadata, Box::new(Cursor::new(file_content.to_owned()))) {
                Ok(nb_bytes_written) if nb_bytes_written == file_metadata.size => Ok(()),
                Ok(nb_bytes_written) => {
                    // Socket or connection hanged while sending file, we will retry
                    warn!("Only {} bytes out of {} were successfully written on attempt {} out of {}, will retry in {}ms",
                        nb_bytes_written, file_content.len(), current_try - 1, SMB_SEND_FILE_NB_ATTEMPTS, SMB_SEND_FILE_RETRY_DELAY_IN_MS);
                    Err(FileSharingError {
                        error: FileTransferFailed,
                        description: "Couldn't fully transfer file to SMB share".to_string(),
                    })
                },
                Err(err) => {
                    let err_msg = err.msg.unwrap_or_else(|| "UNKNOWN".to_string());
                    warn!("Unknown '{:?}' error while transferring file content, got '{}' on attempt {} out of {}, will retry in {}ms",
                        err.kind, err_msg, current_try - 1, SMB_SEND_FILE_NB_ATTEMPTS, SMB_SEND_FILE_RETRY_DELAY_IN_MS);
                    // The network name cannot be found - OS error 67
                    suggest_disconnection = err_msg.contains(&ERROR_BAD_NET_NAME.0.to_string());
                    Err(FileSharingError {
                        error: FileTransferFailed,
                        description: "Cannot transfer file to SMB share".to_string(),
                    })
                }
            }
        });

        return create_file_result.map_err(|send_file_err| {
            if suggest_disconnection {
                warn!("Explicitly disconnecting as last failures seem to indicate we potentially lost connection to the SMB share");
                // Disconnect from the SMB share out of safety so that we reconnect during the next loop
                let _ = self.smb_client.as_mut().unwrap().disconnect();
            }
            send_file_err.error
        });
    }
}