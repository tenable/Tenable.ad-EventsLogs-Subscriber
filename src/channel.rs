use log::{error, info};
use windows::core::Result as WinResult;
use windows::Win32::Foundation::{BOOL, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows::Win32::System::EventLog::*;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
use winreg::RegKey;

pub const DEFAULT_CHANNELS: [&str; 3] = ["Security", "Application", "System"];

fn is_default_channel(channel_name: &str) -> bool {
    DEFAULT_CHANNELS.contains(&&channel_name[..])
}

const WINDOWS_SERVER_2022_BUILD: u32 = 20348;

/// Fix `AD-11331`: On Windows Server 2022, some channels need to be (re)activated with
/// `EvtSetChannelConfigProperty` and `EvtSaveChannelConfig` to refresh the cache.
///
/// The result is `Ok(true)` if the channel was activated and refreshed, or `Ok(false)` if it was
/// not needed. Otherwise, `Err()` is returned if an error occurred.
pub fn try_activate_and_refresh_channel_cache(
    channel: &str,
    preview: bool,
    current_build_number: Option<u32>,
) -> anyhow::Result<bool> {
    if !preview {
        return Ok(false);
    }

    if is_default_channel(channel) {
        info!("Channel '{channel}' is default one");
        return Ok(false);
    }

    match current_build_number {
        Some(n) if n < WINDOWS_SERVER_2022_BUILD => {
            info!(
                "Current version is prior to Windows Server 2022: \
                skipping the channel '{channel}' activation and cache refresh"
            );
            return Ok(false);
        }
        Some(_) => {
            info!("Current version is Windows Server 2022 or later, start refreshing channel '{channel}'");
        }
        None => {
            // Here, we continue the process (even though we don't know the actual build number of
            // the current machine), because:
            // - this value should exist on all Windows versions up to 2022 at least, so if it does
            //   not exist anymore it probably indicate that it is a future version that has moved
            //   or removed it
            // - otherwise, if it does not exist for another reason (if someone has been tempering
            //   with its registry for instance) then there is no major issue to perform these
            //   operations anyway, even if they are not needed
            info!("Could not detect the current Windows version, start refreshing channel '{channel}'");
        }
    }

    info!("Trying to activate and refresh cache for channel '{channel}'");

    let channel_provider = open_channel(channel)?;
    activate_and_refresh_channel_cache(channel, channel_provider)
}

#[cfg(test)]
fn open_channel(_channel_name: &str) -> WinResult<MockChannelProvider> {
    let mut mock = MockChannelProvider::new();

    mock.expect_get_channel_type()
        .times(1)
        .return_const(Ok(EvtChannelTypeAnalytic));

    mock.expect_set_channel_type()
        .times(1)
        .returning(|_| Ok(()));

    mock.expect_is_event_log_key_set()
        .times(1)
        .returning(|| Ok(false));

    mock.expect_backup_event_log_key().times(0);

    mock.expect_is_enabled().times(1).return_const(Ok(false));

    mock.expect_set_enabled_status()
        .times(1)
        .return_const(Ok(()));

    mock.expect_reset_event_log_key().times(0);

    Ok(mock)
}

#[cfg(not(test))]
fn open_channel(channel_name: &str) -> WinResult<WindowsChannelProvider> {
    let channel_handle = unsafe { EvtOpenChannelConfig(0, channel_name, 0x0) };

    if channel_handle == 0 {
        error!("The channel '{channel_name}' could not be opened");
        return Err(windows::core::Error::from_win32());
    }

    let channel_provider = WindowsChannelProvider::new(channel_name.to_string(), channel_handle);
    Ok(channel_provider)
}

fn activate_and_refresh_channel_cache(
    channel_name: &str,
    channel_provider: impl ChannelProvider,
) -> anyhow::Result<bool> {
    // We check if the "Type" of the channel to which we subscribe is set to 0 (Admin) or 1 (Operational)
    let channel_type = channel_provider.get_channel_type()?;
    let is_valid = channel_type == EvtChannelTypeAdmin || channel_type == EvtChannelTypeOperational;
    if is_valid {
        let channel_type_value = channel_type.0;
        info!(
            "The channel '{channel_name}' is of type '{channel_type_value}': ready for listening"
        );
        return Ok(false);
    }

    // Set registry key
    channel_provider.set_channel_type(EvtChannelTypeAdmin)?;

    let is_event_log_key_set = match channel_provider.is_event_log_key_set() {
        Ok(value) => value,
        Err(err) => {
            error!(
                "An error occurred while trying to verify if the EventLog key \
                for channel '{channel_name}' is set: {err}"
            );
            false
        }
    };

    let has_removed_event_log_key = if is_event_log_key_set {
        // Remove EventLog key that can prevent to enable/disable the channel
        match channel_provider.backup_event_log_key() {
            Ok(()) => true,
            Err(err) => {
                // We ignore the error and try to enable the channel anyway
                error!(
                    "An error occurred while trying to remove the EventLog key of the channel '{channel_name}': {err}"
                );
                false
            }
        }
    } else {
        // No need to remove the EventLog key as it doesn't exist
        false
    };

    // Ensure the channel is activated and the cache is refreshed
    let is_enabled = channel_provider.is_enabled()?;
    if is_enabled {
        channel_provider.set_enabled_status(false)?;
    }
    channel_provider.set_enabled_status(true)?;

    if has_removed_event_log_key {
        // Reset the EventLog key that was previously removed
        channel_provider.reset_event_log_key()?;
    }

    Ok(true)
}

#[cfg_attr(test, mockall::automock)]
trait ChannelProvider {
    fn get_channel_type(&self) -> WinResult<EVT_CHANNEL_TYPE>;
    fn set_channel_type(&self, channel_type: EVT_CHANNEL_TYPE) -> std::io::Result<()>;
    fn is_event_log_key_set(&self) -> std::io::Result<bool>;
    fn backup_event_log_key(&self) -> std::io::Result<()>;
    fn reset_event_log_key(&self) -> std::io::Result<()>;
    fn is_enabled(&self) -> WinResult<bool>;
    fn set_enabled_status(&self, status: bool) -> WinResult<()>;
}

struct WindowsChannelProvider {
    channel_name: String,
    channel_handle: isize,
}

impl WindowsChannelProvider {
    #[cfg(not(test))]
    fn new(channel_name: String, channel_handle: isize) -> Self {
        Self {
            channel_name,
            channel_handle,
        }
    }

    fn get_channel_property(
        &self,
        property: *mut EVT_VARIANT,
        config_id: EVT_CHANNEL_CONFIG_PROPERTY_ID,
    ) -> WinResult<()> {
        let mut buffer_used = 0u32;

        unsafe {
            EvtGetChannelConfigProperty(
                self.channel_handle,
                config_id,
                0x0,
                0,
                property,
                &mut buffer_used as _,
            )
        };

        let result = windows::core::Error::from_win32();
        match result.win32_error() {
            Some(ERROR_INSUFFICIENT_BUFFER) => {} // Continue
            Some(ERROR_SUCCESS) => return Ok(()),
            _ => return Err(result),
        };

        // In case of an insufficient buffer we repeat the call with a bigger buffer
        return unsafe {
            EvtGetChannelConfigProperty(
                self.channel_handle,
                config_id,
                0x0,
                buffer_used,
                property,
                &mut buffer_used as _,
            )
        }
        .ok();
    }

    fn move_event_log_key(&self, src_key_name: &str, dest_key_name: &str) -> std::io::Result<()> {
        let root_path = "SYSTEM\\CurrentControlSet\\Services\\EventLog";

        let src_path = format!("{root_path}\\{src_key_name}");
        let dest_path = format!("{root_path}\\{dest_key_name}");

        info!("Opening the root key '{root_path}'");
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let root_key = hklm.open_subkey_with_flags(root_path, KEY_SET_VALUE)?;

        info!("Creating the key '{dest_path}'");
        let (dest_key, _) = hklm.create_subkey(&dest_path)?;

        info!("Copying the key '{src_path}' to key '{dest_path}'");
        root_key.copy_tree(src_key_name, &dest_key)?;

        info!("Removing the key '{src_path}'");
        root_key.delete_subkey_all(src_key_name)?;

        Ok(())
    }
}

impl Drop for WindowsChannelProvider {
    fn drop(&mut self) {
        if self.channel_handle != 0 {
            unsafe { EvtClose(self.channel_handle) };
            self.channel_handle = 0;
        }
    }
}

impl ChannelProvider for WindowsChannelProvider {
    fn get_channel_type(&self) -> WinResult<EVT_CHANNEL_TYPE> {
        let property = EVT_VARIANT::default();
        self.get_channel_property(std::ptr::addr_of!(property) as _, EvtChannelConfigType)?;

        let channel_type = unsafe { property.Anonymous.UInt32Val };
        Ok(EVT_CHANNEL_TYPE(channel_type as i32))
    }

    fn set_channel_type(&self, channel_type: EVT_CHANNEL_TYPE) -> std::io::Result<()> {
        info!(
            "Setting the type of the channel '{}' to '{}'",
            self.channel_name, channel_type.0
        );

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let channel = hklm.open_subkey_with_flags(
            format!(
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\{}",
                self.channel_name
            ),
            KEY_SET_VALUE,
        )?;
        channel.set_value("Type", &(channel_type.0 as u32))?;

        Ok(())
    }

    fn is_event_log_key_set(&self) -> std::io::Result<bool> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let event_log_key = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\EventLog")?;

        Ok(event_log_key
            .enum_keys()
            .filter_map(|k| k.ok())
            .any(|k| k == self.channel_name))
    }

    fn backup_event_log_key(&self) -> std::io::Result<()> {
        self.move_event_log_key(&self.channel_name, &format!("Temp-{}", self.channel_name))?;

        Ok(())
    }

    fn reset_event_log_key(&self) -> std::io::Result<()> {
        self.move_event_log_key(&format!("Temp-{}", self.channel_name), &self.channel_name)?;

        Ok(())
    }

    fn is_enabled(&self) -> WinResult<bool> {
        let property = EVT_VARIANT::default();
        self.get_channel_property(std::ptr::addr_of!(property) as _, EvtChannelConfigEnabled)?;

        Ok(unsafe { property.Anonymous.BooleanVal }.as_bool())
    }

    fn set_enabled_status(&self, status: bool) -> WinResult<()> {
        info!(
            "Setting the channel '{}' enable status to '{status}'",
            self.channel_name
        );

        let channel_property = EVT_VARIANT {
            Type: EvtVarTypeBoolean.0 as _,
            Count: 0,
            Anonymous: EVT_VARIANT_0 {
                BooleanVal: BOOL::from(status),
            },
        };

        unsafe {
            EvtSetChannelConfigProperty(
                self.channel_handle,
                EvtChannelConfigEnabled,
                0x0,
                std::ptr::addr_of!(channel_property) as _,
            )
        }
        .ok()?;

        // The user needs to be in the administrators group and be running with
        // elevated permissions for this call to work.
        info!("Saving the channel '{}'", self.channel_name);
        unsafe { EvtSaveChannelConfig(self.channel_handle, 0x0) }.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod try_activate_and_refresh_channel_cache {
        use super::*;

        #[test]
        fn it_should_return_ok_false_while_in_preview() {
            // Act
            let result = try_activate_and_refresh_channel_cache(
                "test",
                false,
                Some(WINDOWS_SERVER_2022_BUILD),
            );

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }

        #[test]
        fn it_should_return_ok_false_for_a_default_channel() {
            // Act
            let result = try_activate_and_refresh_channel_cache(
                "Security",
                true,
                Some(WINDOWS_SERVER_2022_BUILD),
            );

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }

        #[test]
        fn it_should_return_ok_false_for_a_build_prior_to_win_server_2022() {
            // Act
            let result = try_activate_and_refresh_channel_cache(
                "test",
                true,
                Some(WINDOWS_SERVER_2022_BUILD - 1),
            );

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }

        #[test]
        fn it_should_return_ok_true_when_all_prerequisties_are_valid() {
            // Act
            let result = try_activate_and_refresh_channel_cache(
                "test",
                true,
                Some(WINDOWS_SERVER_2022_BUILD),
            );

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }
    }

    mod activate_and_refresh_channel_cache {
        use super::*;
        use mockall::predicate::*;

        #[test]
        fn it_should_return_ok_false_for_a_channel_admin() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeAdmin));

            mock.expect_set_channel_type().times(0);
            mock.expect_is_event_log_key_set().times(0);
            mock.expect_backup_event_log_key().times(0);
            mock.expect_reset_event_log_key().times(0);
            mock.expect_is_enabled().times(0);
            mock.expect_set_enabled_status().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }

        #[test]
        fn it_should_return_ok_false_for_a_channel_operational() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeOperational));

            mock.expect_set_channel_type().times(0);
            mock.expect_is_event_log_key_set().times(0);
            mock.expect_backup_event_log_key().times(0);
            mock.expect_is_enabled().times(0);
            mock.expect_set_enabled_status().times(0);
            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), false);
        }

        #[test]
        fn it_should_continue_for_a_channel_analytic() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeAnalytic));

            mock.expect_set_channel_type()
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(false));

            mock.expect_backup_event_log_key().times(0);

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }

        #[test]
        fn it_should_continue_for_a_channel_debug() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(false));

            mock.expect_backup_event_log_key().times(0);

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }

        #[test]
        fn it_should_set_the_channel_type_to_admin() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(false));

            mock.expect_backup_event_log_key().times(0);

            mock.expect_is_enabled().return_const(Ok(true));

            mock.expect_set_enabled_status().return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }

        #[test]
        fn it_should_abort_if_it_can_not_set_the_channel_type_to_admin() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Err(std::io::ErrorKind::Other.into()));

            mock.expect_is_event_log_key_set().times(0);
            mock.expect_backup_event_log_key().times(0);
            mock.expect_is_enabled().times(0);
            mock.expect_set_enabled_status().times(0);
            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_err());
        }

        #[test]
        fn it_should_ignore_and_continue_if_it_can_not_get_the_event_log_key() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Err(std::io::ErrorKind::Other.into()));

            mock.expect_backup_event_log_key().times(0);

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .with(eq(false))
                .times(0)
                .return_const(Ok(()));

            mock.expect_set_enabled_status()
                .with(eq(true))
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
        }

        #[test]
        fn it_should_ignore_and_continue_if_it_can_not_backup_the_event_log_key() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(true));

            mock.expect_backup_event_log_key()
                .times(1)
                .returning(|| Err(std::io::ErrorKind::Other.into()));

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .with(eq(false))
                .times(0)
                .return_const(Ok(()));

            mock.expect_set_enabled_status()
                .with(eq(true))
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
        }

        #[test]
        fn it_should_raise_an_error_if_it_cannot_reset_the_event_log_key() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(true));

            mock.expect_backup_event_log_key()
                .times(1)
                .returning(|| Ok(()));

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .with(eq(false))
                .times(0)
                .return_const(Ok(()));

            mock.expect_set_enabled_status()
                .with(eq(true))
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key()
                .times(1)
                .returning(|| Err(std::io::ErrorKind::Other.into()));

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_err());
        }

        #[test]
        fn it_should_backup_and_reset_the_key_if_it_is_set() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(true));

            mock.expect_backup_event_log_key()
                .times(1)
                .returning(|| Ok(()));

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .with(eq(false))
                .times(0)
                .return_const(Ok(()));

            mock.expect_set_enabled_status()
                .with(eq(true))
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key()
                .times(1)
                .returning(|| Ok(()));

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
        }

        #[test]
        fn it_should_not_backup_and_reset_the_key_if_it_is_not_set() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(false));

            mock.expect_backup_event_log_key().times(0);

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .with(eq(false))
                .times(0)
                .return_const(Ok(()));

            mock.expect_set_enabled_status()
                .with(eq(true))
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
        }

        #[test]
        fn it_should_deactivate_and_reactivate_if_enabled() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(false));

            mock.expect_backup_event_log_key().times(0);

            mock.expect_is_enabled().times(1).return_const(Ok(true));

            mock.expect_set_enabled_status()
                .with(eq(false))
                .times(1)
                .return_const(Ok(()));

            mock.expect_set_enabled_status()
                .with(eq(true))
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }

        #[test]
        fn it_should_activate_if_disabled() {
            // Arrange
            let mut mock = MockChannelProvider::new();

            mock.expect_get_channel_type()
                .times(1)
                .return_const(Ok(EvtChannelTypeDebug));

            mock.expect_set_channel_type()
                .with(eq(EvtChannelTypeAdmin))
                .times(1)
                .returning(|_| Ok(()));

            mock.expect_is_event_log_key_set()
                .times(1)
                .returning(|| Ok(false));

            mock.expect_backup_event_log_key().times(0);

            mock.expect_is_enabled().times(1).return_const(Ok(false));

            mock.expect_set_enabled_status()
                .with(eq(false))
                .times(0)
                .return_const(Ok(()));

            mock.expect_set_enabled_status()
                .with(eq(true))
                .times(1)
                .return_const(Ok(()));

            mock.expect_reset_event_log_key().times(0);

            // Act
            let result = activate_and_refresh_channel_cache("test", mock);

            // Assert
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), true);
        }
    }
}
