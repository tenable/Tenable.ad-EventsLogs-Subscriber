use crate::EventLog;
use clap::Parser;
use log::info;
use serde::Deserialize;
use std::collections::HashSet;
use std::num::NonZeroU8;
use std::path::Path;

#[cfg(test)]
use crate::EMPTY_STRING;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use tempfile::NamedTempFile;

#[derive(Deserialize)]
pub struct EventsLogsConfiguration {
    #[serde(alias = "Events", alias = "events")]
    pub(crate) events: Vec<EventLog>,

    #[serde(alias = "Channels", alias = "channels")]
    pub(crate) channels: Vec<String>,

    #[serde(alias = "Audit", alias = "audit")]
    pub(crate) audit: Vec<String>,

    #[serde(alias = "RegistryValues", alias = "registryValues")]
    pub(crate) registry_values: Vec<String>,

    #[serde(alias = "PolRegistryValues", alias = "polRegistryValues")]
    pub(crate) pol_values: Vec<String>,

    #[serde(alias = "SmbModeActivated", alias = "smbModeActivated")]
    #[serde(default)]
    pub(crate) smb_mode_activated: bool,

    #[serde(alias = "RelayAccountUsername", alias = "relayAccountUsername")]
    #[serde(default)]
    pub(crate) relay_account_username: String,
}

impl PartialEq for EventsLogsConfiguration {
    fn eq(&self, other: &Self) -> bool {
        let self_events: HashSet<&EventLog> = self.events.iter().collect();
        let self_channels: HashSet<&String> = self.channels.iter().collect();
        let self_audit: HashSet<&String> = self.audit.iter().collect();
        let self_registry_values: HashSet<&String> = self.registry_values.iter().collect();
        let self_pol_values: HashSet<&String> = self.pol_values.iter().collect();

        let other_events: HashSet<&EventLog> = other.events.iter().collect();
        let other_channels: HashSet<&String> = other.channels.iter().collect();
        let other_audit: HashSet<&String> = other.audit.iter().collect();
        let other_registry_values: HashSet<&String> = other.registry_values.iter().collect();
        let other_pol_values: HashSet<&String> = other.pol_values.iter().collect();

        self_events == other_events
            && self_channels == other_channels
            && self_audit == other_audit
            && self_registry_values == other_registry_values
            && self_pol_values == other_pol_values
            && self.smb_mode_activated == other.smb_mode_activated
            && self.relay_account_username == other.relay_account_username
    }
}

#[cfg(test)]
impl Default for EventsLogsConfiguration {
    fn default() -> Self {
        Self {
            events: vec![],
            channels: vec![],
            audit: vec![],
            registry_values: vec![],
            pol_values: vec![],
            smb_mode_activated: false,
            relay_account_username: EMPTY_STRING.to_string(),
        }
    }
}

impl EventsLogsConfiguration {
    #[cfg(test)]
    pub fn with_smb_mode_activated(mut self, smb_mode_activated: bool) -> Self {
        self.smb_mode_activated = smb_mode_activated;
        self
    }

    #[cfg(test)]
    pub fn with_relay_account_username(mut self, relay_account_username: &str) -> Self {
        self.relay_account_username = relay_account_username.to_string();
        self
    }

    pub fn read_setup_from_file(path: &Path) -> std::io::Result<(EventsLogsConfiguration, String)> {
        info!("Reading setup from file {}", path.display());

        let configuration_file_content = std::fs::read_to_string(path)?;
        let configuration_file_json: EventsLogsConfiguration =
            serde_json::from_str(&configuration_file_content)?;

        Ok((configuration_file_json, configuration_file_content))
    }

    /// Create a temporary file for test config
    #[cfg(test)]
    pub fn create_configuration_file(content: &[u8]) -> NamedTempFile {
        let mut tmp_file =
            NamedTempFile::new().expect("Unable to create temporary file for the test.");
        tmp_file
            .as_file_mut()
            .write_all(content)
            .expect("Unable to write in a temporary file for the test.");
        return tmp_file;
    }

    #[cfg(test)]
    pub fn create_default_configuration_file() -> NamedTempFile {
        return Self::create_configuration_file(
            br#"{
  "Events": [
    {
      "Id": 541,
      "ProviderName": "Microsoft-Windows-DNSServer"
    },
    {
      "Id": 4624,
      "ProviderName": "Microsoft-Windows-Security-Auditing"
    }
  ],
  "Channels": [
    "Setup"
  ],
  "Audit": [],
  "RegistryValues": [],
  "PolRegistryValues": [],
  "SmbModeActivated": false,
  "RelayAccountUsername": ""
}"#,
        );
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(
    about = "This command launches an event listener, which forwards each received event to an internal memory buffer. This buffer is flushed to the disk periodically."
)]
pub struct Arguments {
    #[clap(
        short = 'p',
        long = "EventLogFilePath",
        help = "The file where events are written"
    )]
    pub(crate) event_log_file_path: String,

    #[clap(
        short = 't',
        long = "TimerDurationSeconds",
        help = "The interval between each file write"
    )]
    pub(crate) timer_duration_seconds: u32,

    #[clap(
        short = 'b',
        long = "MaxBufferSizeBytes",
        default_value = "524288000",
        help = "The maximum buffer size in bytes"
    )]
    pub(crate) max_buffer_size_bytes: usize,

    #[clap(
        short = 's',
        long = "MaxThroughput",
        default_value = "1500",
        help = "The maximum handled throughput, in event logs per second"
    )]
    pub(crate) max_throughput: u32,

    #[clap(
        short = 'd',
        long = "DurationLeapMilliSeconds",
        default_value = "10",
        help = "The duration leap to adjust events logs consumption throughput, in milliseconds"
    )]
    pub(crate) duration_leap: u64,

    #[clap(
        short = 'g',
        long = "EnableGzip",
        action,
        help = "Whether GZip compression is enabled"
    )]
    pub(crate) enable_gzip: bool,

    #[clap(
        short = 'r',
        long = "CpuRate",
        default_value = "20",
        help = "Control the CPU rate of the process (does not work on Windows Sever 2008R2 and below)"
    )]
    pub(crate) cpu_rate: NonZeroU8,

    #[clap(
        short = 'w',
        long = "Preview",
        action,
        help = "Enable preview features"
    )]
    pub(crate) preview: bool,

    #[clap(
        long = "Debug",
        action,
        help = "Enable debug logging within the program. This option is disabled by default."
    )]
    pub(crate) debug: bool,

    #[clap(
        short = 'f',
        long = "AuditFolder",
        help = "Path of the folder containing the audit.csv file in the GPO"
    )]
    pub(crate) audit_folder: String,

    #[clap(
        short = 'a',
        long = "AdministratorName",
        help = "Name of the administrator account that can be used to execute some operations"
    )]
    pub(crate) administrator_name: String,

    #[clap(short = 'i', long = "PdcName", help = "Name of the PDC")]
    pub(crate) pdc_name: String,

    #[clap(short = 'y', long = "DomainName", help = "Name of the domain")]
    pub(crate) domain_name: String,

    #[clap(
        short = 'z',
        long = "DomainControllerDnsName",
        help = "DNS name of the domain controller"
    )]
    pub(crate) domain_controller_dns_name: String,

    #[clap(
        short = 'x',
        long = "GptTmplFile",
        help = "Path of the GptTmpl.inf file in the GPO"
    )]
    pub(crate) gpt_tmpl_file: String,

    #[clap(
        short = 'l',
        long = "RegistryPolFile",
        help = "Path of the Registry.pol file in the GPO"
    )]
    pub(crate) registry_pol_file: String,

    #[clap(
        long = "ConfigurationUpdateIntervalInMinutes",
        default_value = "5",
        help = "Minimum interval between each configuration update"
    )]
    pub(crate) conf_interval_in_minutes: NonZeroU8,

    #[clap(
        long = "SmbShareLocation",
        default_value = "C:\\Tenable\\IdentityExposure\\IOALogs",
        help = "Physical disk location (absolute path) for the SMB share when running on the PDCe"
    )]
    pub(crate) smb_share_location: String,

    #[clap(
        long = "UseXmlEventRender",
        help = "Allows to use the legacy XML event rendering method for listeners. Although slower than the current values-based approach, it provides greater stability. This option is disabled by default."
    )]
    pub(crate) use_xml_render: bool,
}

#[cfg(test)]
impl Default for Arguments {
    fn default() -> Self {
        Self {
            event_log_file_path: "./EventLogs.gz".to_string(),
            timer_duration_seconds: 15,
            max_buffer_size_bytes: 524288000,
            max_throughput: 1500,
            duration_leap: 10,
            enable_gzip: true,
            cpu_rate: NonZeroU8::new(20).unwrap(),
            preview: true,
            debug: false,
            audit_folder: EMPTY_STRING.to_string(),
            administrator_name: EMPTY_STRING.to_string(),
            pdc_name: EMPTY_STRING.to_string(),
            domain_name: EMPTY_STRING.to_string(),
            domain_controller_dns_name: EMPTY_STRING.to_string(),
            gpt_tmpl_file: EMPTY_STRING.to_string(),
            registry_pol_file: EMPTY_STRING.to_string(),
            conf_interval_in_minutes: NonZeroU8::new(5).unwrap(),
            smb_share_location: "C:\\Tenable\\IdentityExposure\\IOALogs".to_string(),
            use_xml_render: false,
        }
    }
}

#[cfg(test)]
mod tests {
    mod event_log_configuration {
        use super::super::*;

        #[test]
        fn it_should_say_not_equal_on_config_with_different_smb_mode_activated() {
            // Arrange
            let before = EventsLogsConfiguration::default().with_smb_mode_activated(false);
            let after = EventsLogsConfiguration::default().with_smb_mode_activated(true);

            // Act
            let comparison = before == after;

            // Assert
            assert_eq!(false, comparison);
        }

        #[test]
        fn it_should_say_not_equal_on_config_with_different_relay_account_usernames() {
            // Arrange
            let before = EventsLogsConfiguration::default().with_relay_account_username("foo");
            let after = EventsLogsConfiguration::default().with_relay_account_username("bar");

            // Act
            let comparison = before == after;

            // Assert
            assert_eq!(false, comparison);
        }

        #[test]
        fn it_should_say_same_configurations_are_equal() {
            // Arrange
            let before = EventsLogsConfiguration::default();
            let after = EventsLogsConfiguration::default();

            // Act
            let comparison = before == after;

            // Assert
            assert_eq!(true, comparison);
        }

        /// This test ensure that the listener can receive a config without the `SmbModeActivated` boolean
        /// This can happen as we will introduce support for the configuration value before it is produced inside the configuration
        #[test]
        fn it_should_default_smb_mode_to_false_on_no_value() {
            // Arrange: Fake some old configuration that could be fed to this listener without the value
            let raw_configuration_file_content: &[u8] = br#"{
  "Events": [
    {
      "Id": 541,
      "ProviderName": "Microsoft-Windows-DNSServer"
    },
    {
      "Id": 4624,
      "ProviderName": "Microsoft-Windows-Security-Auditing"
    }
  ],
  "Channels": [
    "Setup"
  ],
  "Audit": [],
  "RegistryValues": [],
  "PolRegistryValues": []
  }"#;
            let tmp_config_file =
                EventsLogsConfiguration::create_configuration_file(raw_configuration_file_content);

            // Act
            let read_config = EventsLogsConfiguration::read_setup_from_file(tmp_config_file.path());

            // Asserts
            assert!(read_config.is_ok());
            let (config, _) = read_config.unwrap();
            assert_eq!(false, config.smb_mode_activated);
            assert_eq!(EMPTY_STRING.to_string(), config.relay_account_username);
        }

        #[test]
        fn it_should_report_error_on_invalid_json_file() {
            // Arrange
            let wrong_config: &[u8] = br#"JSON error"#;
            let tmp_config_file = EventsLogsConfiguration::create_configuration_file(wrong_config);

            // Act
            let read_config = EventsLogsConfiguration::read_setup_from_file(tmp_config_file.path());

            // Assert
            assert!(read_config.is_err());
        }

        #[test]
        fn it_should_be_able_to_read_full_config_from_json_file() {
            // Arrange
            let raw_configuration_file_content: &[u8] = br#"{
  "Events": [
    {
      "Id": 42,
      "ProviderName": "Provider"
    }
  ],
  "Channels": ["TestChannel"],
  "Audit": ["TestAudit"],
  "RegistryValues": ["TestRegistryValues"],
  "PolRegistryValues": ["TestPolRegistryValues"],
  "SmbModeActivated": true,
  "RelayAccountUsername": "svcRelayTenable",
  "IgnoredField": "IWillBeIgnoredBySerde"
  }"#;
            let tmp_config_file =
                EventsLogsConfiguration::create_configuration_file(raw_configuration_file_content);

            // Act
            let read_config = EventsLogsConfiguration::read_setup_from_file(tmp_config_file.path());

            // Asserts
            assert!(read_config.is_ok());
            let (config, _) = read_config.unwrap();
            assert_eq!(1, config.events.len());
            assert_eq!(config.events.first().unwrap().id, 42);
            assert_eq!(config.events.first().unwrap().provider_name, "Provider");
            assert_eq!(vec!["TestChannel".to_string()], config.channels);
            assert_eq!(vec!["TestAudit".to_string()], config.audit);
            assert_eq!(
                vec!["TestRegistryValues".to_string()],
                config.registry_values
            );
            assert_eq!(vec!["TestPolRegistryValues".to_string()], config.pol_values);
            assert_eq!(true, config.smb_mode_activated);
            assert_eq!("svcRelayTenable", config.relay_account_username);
        }
    }
}
