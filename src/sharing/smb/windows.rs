use std::ptr::null_mut;
use log::{error, info, warn};
use retry::delay::Fixed;
use retry::retry_with_index;
use serde::Deserialize;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Storage::FileSystem::{NetShareAdd, NetShareDel, NetShareGetInfo, ACCESS_ALL, SHARE_INFO_2, STYPE_DISKTREE};
use windows::Win32::NetworkManagement::NetManagement::{NERR_Success, NERR_DuplicateShare, NERR_NetNameNotFound, NetApiBufferFree};
use crate::helpers::{convert_pwstr_to_string, WindowsStringHelpers};
use crate::powershell::get_powershell_output_lossy;
use crate::sharing::errors::FileSharingError;
use crate::sharing::errors::FileSharingFailureReason::{SetupError, DisableError};

#[derive(Deserialize)]
pub struct SmbServerConfiguration {
    #[serde(alias = "EnableSMB1Protocol")]
    smb1_enabled: bool,

    #[serde(alias = "EnableSMB2Protocol")]
    smb2_enabled: bool,
}

#[cfg_attr(test, mockall::automock)]
pub trait SmbPlatformSpecificActions {
    fn create_smb_share(
        &self,
        pdce_hostname: &String,
        share_name: &str,
        physical_location: &String,
        comment: &str,
    ) -> Result<(), FileSharingError>;
    fn delete_smb_share(&self, pdce_hostname: &String, smb_share_name: &str) -> Result<(), FileSharingError>;
    fn secure_smb_folder_access(&self, physical_location: &String, relay_account: &String) -> Result<(), FileSharingError>;
    fn secure_smb_share_access(&self, share_name: &str, relay_account: &String) -> Result<(), FileSharingError>;
    fn is_smb_enabled(&self) -> bool;
    fn get_smb_share_physical_location(&self, share_name: &str) -> Option<String>;
}

#[derive(Default)]
pub struct WindowsSmbPlatformSpecificActions;

/// Delay in ms between each call to the Windows API
const WINAPI_CALL_RETRY_DELAY_MS: u64 = 500;
/// Number of attempts when calling Windows API
const WINAPI_CALL_NB_ATTEMPTS: usize = 3;

impl SmbPlatformSpecificActions for WindowsSmbPlatformSpecificActions {
    /// Creates an SMB share on Windows using the WinAPI
    /// See https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareadd
    /// See https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_2
    fn create_smb_share(
        &self,
        pdce_hostname: &String,
        share_name: &str,
        physical_location: &String,
        comment: &str,
    ) -> Result<(), FileSharingError> {
        info!("Trying creation of '{}\\{}' SMB share at '{}'...", pdce_hostname, share_name, physical_location);
        let mut err_param: u32 = 0;
        // Hold the variables so they stay in the same scope as the structure
        let win_smb_share_name = share_name.to_pwstr();
        let win_smb_comment = comment.to_pwstr();
        let win_physical_location = physical_location.to_pwstr();

        let share_info = SHARE_INFO_2 {
            shi2_netname: win_smb_share_name.0,
            shi2_type: STYPE_DISKTREE,
            shi2_remark: win_smb_comment.0,
            shi2_permissions: ACCESS_ALL,
            shi2_max_uses: 1000,
            shi2_current_uses: 0,
            shi2_path: win_physical_location.0,
            shi2_passwd: PWSTR::default(),
        };
        return retry_with_index(Fixed::from_millis(WINAPI_CALL_RETRY_DELAY_MS).take(WINAPI_CALL_NB_ATTEMPTS), |current_try| {
            unsafe {
                let smb_create_result = NetShareAdd(
                    PCWSTR::default(),
                    2, // SHARE_INFO_2
                    &share_info as *const _ as *const u8,
                    &mut err_param,
                );
                match smb_create_result {
                    0 => {
                        info!("SMB share has been successfully created on '{}\\{}'", pdce_hostname, share_name);
                        Ok(())
                    },
                    NERR_DuplicateShare => {
                        info!("SMB share '{}\\{}' already exists", pdce_hostname, share_name);
                        Ok(())
                    },
                    _ => {
                        warn!("Error while creating SMB share, code {} (param code {}) on attempt {} out of {}, will retry in {}ms",
                            smb_create_result, err_param, current_try - 1, WINAPI_CALL_NB_ATTEMPTS, WINAPI_CALL_RETRY_DELAY_MS);
                        Err(FileSharingError {
                            error: SetupError,
                            description: format!("Error while creating SMB share, code {smb_create_result} (param code {err_param})"),
                        })
                    }
                }
            }
        }).map_err(|retry_err| retry_err.error);
    }

    fn delete_smb_share(&self, pdce_hostname: &String, smb_share_name: &str) -> Result<(), FileSharingError> {
        return retry_with_index(Fixed::from_millis(WINAPI_CALL_RETRY_DELAY_MS).take(WINAPI_CALL_NB_ATTEMPTS), |current_try| {
            unsafe {
                let delete_smb_share = NetShareDel(
                    PCWSTR::default(),
                    smb_share_name,
                    0,
                );
                match delete_smb_share {
                    NERR_Success => {
                        info!("SMB share '{}\\{}' has been deleted", pdce_hostname, smb_share_name);
                        Ok(())
                    },
                    NERR_NetNameNotFound => { // 2310
                        warn!("SMB share '{}\\{}' was not found, will consider it's already deleted", pdce_hostname, smb_share_name);
                        Ok(())
                    },
                    _ => {
                        warn!("Error while deleting SMB share, code {} on attempt {} out of {}, will retry in {}ms",
                            delete_smb_share, current_try - 1, WINAPI_CALL_NB_ATTEMPTS, WINAPI_CALL_RETRY_DELAY_MS);
                        Err(FileSharingError {
                            error: DisableError,
                            description: format!("Error while deleting SMB share, code {}", delete_smb_share),
                        })
                    }
                }
            }
        }).map_err(|retry_err| retry_err.error);
    }

    /// Secure the physical folder of the SMB share
    fn secure_smb_folder_access(&self, physical_location: &String, relay_account: &String) -> Result<(), FileSharingError> {
        let secure_folder_script = format!("\
            $domainSid = (Get-ADDomain).DomainSID;\
            $physicalFolderLocation = '{}';\
            $relaySvcAccountName = '{}';\
            icacls.exe $physicalFolderLocation /grant \"*$domainSid-516:(OI)(CI)F\" \"*$domainSid-512:(OI)(CI)F\" \"*S-1-5-18:(OI)(CI)F\" /T;\
            if (![string]::IsNullOrEmpty($relaySvcAccountName)) {{\
                icacls.exe $physicalFolderLocation /grant \"${{relaySvcAccountName}}:(OI)(CI)RX\" /T;\
            }}
        ", physical_location, relay_account);

        get_powershell_output_lossy(secure_folder_script)
            .map_err(|err| FileSharingError {
                error: SetupError,
                description: format!("Error while trying to secure SMB folder physical access, got '{}'", err.to_string()),
            })?;

        return Ok(());
    }

    /// Configures access rights and ownership of the SMB share
    ///
    /// Note: We don't control nor modify the whole SMB server configuration (i.e. SMB version or signing/encryption) as it's the customer responsibility
    fn secure_smb_share_access(&self, share_name: &str, relay_account: &String) -> Result<(), FileSharingError> {
        let secure_smb_share_script = format!("\
            $domainSid = (Get-ADDomain).DomainSID;\
            $shareName = '{}';\
            $relaySvcAccountName = '{}';\
            Get-SmbShareAccess -Name $shareName | ForEach-Object {{ Revoke-SmbShareAccess -Name $shareName -AccountName $_.AccountName -Force 1> $null }};\
            Grant-SmbShareAccess -Name $shareName -AccountName \"*$domainSid-512\" -AccessRight Full -Force 1> $null;\
            Grant-SmbShareAccess -Name $shareName -AccountName \"*$domainSid-516\" -AccessRight Change -Force 1> $null;\
            if (![string]::IsNullOrEmpty($relaySvcAccountName)) {{\
                Grant-SmbShareAccess -Name $shareName -AccountName $relaySvcAccountName -AccessRight Read -Force 1> $null;\
            }}\
            Get-SmbShareAccess -Name $shareName;
        ", share_name, relay_account);

        get_powershell_output_lossy(secure_smb_share_script)
            .map_err(|err| FileSharingError {
                error: SetupError,
                description: format!("Error while trying to secure SMB share access, got '{}'", err.to_string())
            })?;

        return Ok(());
    }

    /// Basic check to ensure at least SMB v1 is enabled on the PDCe
    /// See https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server#how-to-detect-status-enable-and-disable-smb-protocols
    fn is_smb_enabled(&self) -> bool {
        let smb_config = get_powershell_output_lossy("Get-SmbServerConfiguration | Select-Object -Property EnableSMB1Protocol, EnableSMB2Protocol | ConvertTo-Json");
        if smb_config.is_err() {
            error!("Cannot read SMB server configuration. Will still attempt to initiate SMB connection");
            // We can still give it a chance as it could be a fluke while reading Powershell results. WinAPI will give the final say anyway
            return true;
        }
        let read_smb_server_config: Result<SmbServerConfiguration, _> = serde_json::from_str(smb_config.unwrap().as_str());
        if read_smb_server_config.is_err() {
            error!("Cannot map SMB server configuration to expected object. Will still attempt to initiate SMB connection");
            return true;
        }
        let smb_server_config = read_smb_server_config.unwrap();
        if smb_server_config.smb1_enabled && !smb_server_config.smb2_enabled {
            warn!("Only SMBv1 is enabled on this machine. Please enable SMBv2 and try again.");
            return false;
        }
        if !smb_server_config.smb2_enabled {
            warn!("SMBv2 is disabled on this machine. Please enable SMBv2 and try again.");
            return false
        }
        return true;
    }

    /// Retrieve the current physical folder backing our SMB share
    /// This is useful in scenarios where the customer changed the directory and the current SmbShareLocation passed in the parameter reflects the new location
    /// With this, we can delete the actual folder for the SMB share and not the "potential" new desired one
    fn get_smb_share_physical_location(&self, share_name: &str) -> Option<String> {
        unsafe {
            // Allocate buffer for the local path
            let mut share_info_buf_ptr: *mut SHARE_INFO_2 = null_mut();
            let win_share_name = share_name.to_pcwstr();
            let ask_smb_share_information = NetShareGetInfo(
                PCWSTR::default(), // Local machine
                win_share_name.0,
                2, // SHARE_INFO_2
                &mut share_info_buf_ptr as *mut _ as *mut _,
            );

            return match ask_smb_share_information {
                NERR_Success => {
                    let share_info = &*share_info_buf_ptr;
                    let physical_folder = convert_pwstr_to_string(share_info.shi2_path);
                    NetApiBufferFree(share_info_buf_ptr as *mut _);
                    info!("Existing SMB share '{}' detected and backed by '{}' physical directory", share_name, physical_folder);
                    Some(physical_folder)
                },
                NERR_NetNameNotFound => None,
                _ => {
                    warn!("Error while trying to find physical directory of SMB share '{}', got error code {}",
                        share_name, ask_smb_share_information);
                    None
                }
            }
        }
    }
}