use crate::{
    build_xml_query,
    channel::{is_default_channel, try_activate_and_refresh_channel_cache, DEFAULT_CHANNELS},
    Arguments, EventLog, EventsLogsConfiguration, PREVIEW,
};
use log::{error, info, warn};
use minidom::{Element, NSChoice};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    ptr::null_mut,
};
use tempfile::TempDir;
use windows::Win32::{
    Foundation::{GetLastError, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_QUERY, WIN32_ERROR},
    System::EventLog::{EvtClose, EvtSubscribe, EVT_SUBSCRIBE_CALLBACK},
};
use winreg::{
    enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE},
    RegKey,
};

pub const SYNC_FILE_PATH: &str = "./sync";

#[derive(Clone, Copy)]
pub enum FileChanged {
    ConfigurationChanged,
    SyncFileChanged,
}

pub fn read_setup_from_file(path: &Path) -> std::io::Result<(EventsLogsConfiguration, String)> {
    info!("Reading setup from file {}", path.display());

    let configuration_file_content = std::fs::read_to_string(path)?;
    let configuration_file_json: EventsLogsConfiguration =
        serde_json::from_str(&configuration_file_content)?;

    Ok((configuration_file_json, configuration_file_content))
}

pub fn handle_file_changes(
    path: &Path,
    subscribed_channels: &mut HashMap<String, isize>,
    args: &Arguments,
    callback: EVT_SUBSCRIBE_CALLBACK,
    current_build_number: Option<u32>,
    current_configuration: &mut EventsLogsConfiguration,
    file_changed: FileChanged,
    is_pdc: bool,
) {
    let (configuration_file_json, configuration_file_content) = match read_setup_from_file(path) {
        Ok(result) => result,
        Err(err) => {
            // TODO: Add a retry mechanism?
            error!("An error occurred while reading the setup file: {err}");
            return;
        }
    };

    log_configuration(configuration_file_content, args);

    // Ensure that the current and new configuration are different before trying to do anything.
    match file_changed {
        FileChanged::ConfigurationChanged => {
            if *current_configuration == configuration_file_json {
                info!("The previously applied configuration and the new one are equivalent, ignoring the new configuration");
                return;
            }

            unsubscribe_all_channels(subscribed_channels);

            subscribed_channels.clear();

            if let Err(err) = generate_audit_csv(
                &configuration_file_json.audit,
                args.audit_folder.clone().into(),
                &args.administrator_name[..],
                is_pdc,
            ) {
                error!("An error occurred while trying to generate the audit.csv file: {err}");
            }

            if let Err(err) = generate_gpt_tmpl_inf(
                &configuration_file_json.registry_values,
                args.gpt_tmpl_file.clone().into(),
                is_pdc,
            ) {
                error!("An error occurred while trying to generate the GptTmpl.inf file: {err}");
            }

            if let Err(err) = generate_registry_pol(
                &configuration_file_json.pol_values,
                &args.registry_pol_file[..],
                &args.domain_name[..],
                &args.domain_controller_dns_name[..],
                is_pdc,
            ) {
                error!("An error occurred while trying to generate the Registry.pol file: {err}");
            }

            if let Err(err) = run_command("gpupdate /force") {
                error!("An error occurred while trying to force the GP update: {err}");
            }

            subscribe_to_channels(
                callback,
                current_build_number,
                &configuration_file_json,
                subscribed_channels,
            );

            *current_configuration = configuration_file_json;

            // Change the sync file to tell other DCs that they can resubscribe
            update_sync_file();
        }
        // When any file other than the configuration file is modified, we only want to update our subscriptions to the channels.
        _ => {
            unsubscribe_all_channels(subscribed_channels);

            subscribed_channels.clear();

            if let Err(err) = run_command("gpupdate /force") {
                error!("An error occurred while trying to force the GP update: {err}");
            }

            subscribe_to_channels(
                callback,
                current_build_number,
                &configuration_file_json,
                subscribed_channels,
            );
        }
    };
}

/// Update of the synchronization file in the current folder:
///
/// 1. Reads the current value of the synchronization file.
//     Uses the first byte as a version number.
///    If the file does not exist it sets the version number to 0.
///
/// 2. Increments the version number.
///    If the value of the version number cannot hold into one byte (max 255) it loops back to 0.
///
/// 3. Creates or modifies the synchronization file with the new version number.
///    Retries every five seconds if the write failed.
fn update_sync_file() {
    let version = match std::fs::read(SYNC_FILE_PATH) {
        Ok(content) => content.get(0).copied().unwrap_or(0),
        Err(_) => 0,
    };

    let version = version.wrapping_add(1);

    while let Err(err) = std::fs::write(SYNC_FILE_PATH, [version]) {
        error!(
            "The content of the sync file {SYNC_FILE_PATH} could not be written, \
            retry in 5 seconds: {err}"
        );
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    info!("The version of the sync file {SYNC_FILE_PATH} has been set to {version}");
}

pub fn generate_registry_pol(
    pol_values: &[String],
    registry_pol_file: &str,
    domain_name: &str,
    domain_controller_dns_name: &str,
    is_pdc: bool,
) -> anyhow::Result<()> {
    if !is_pdc {
        info!("The current DC is not the PDC so it does not need to generate registry policies");
        return Ok(());
    }

    let registry_pol_file: PathBuf = registry_pol_file.into();
    if registry_pol_file.exists() {
        if let Err(err) = std::fs::remove_file(&registry_pol_file) {
            error!(
                "An error occurred while trying to remove file at {}: {err}",
                registry_pol_file.display()
            );
        }
    }

    for pol_value in pol_values {
        if let Some(RegistryPolicy {
            reg_path,
            reg_value_name,
            reg_type,
            final_reg_value,
        }) = get_registry_policy(pol_value)
        {
            get_powershell_output(format!(
                "Set-GPRegistryValue \
                    -Name Tenable.ad \
                    -Key '{reg_path}' \
                    -ValueName '{reg_value_name}' \
                    -Type {reg_type} \
                    -Value {final_reg_value} \
                    -Domain {domain_name} \
                    -Server {domain_controller_dns_name}",
            ))?;
        }
    }

    Ok(())
}

fn get_registry_policy(pol_value: &String) -> Option<RegistryPolicy> {
    if let Some((key, value)) = pol_value.split_once('=') {
        if let Some((reg_type, final_reg_value)) = value.split_once(',') {
            if let Some((reg_path, reg_value_name)) = key.rsplit_once('\\') {
                return Some(RegistryPolicy {
                    reg_path: reg_path.to_string(),
                    reg_value_name: reg_value_name.to_string(),
                    reg_type: reg_type.to_string(),
                    final_reg_value: final_reg_value.to_string(),
                });
            }
        }
    }

    None
}

#[derive(Debug, PartialEq)]
struct RegistryPolicy {
    reg_path: String,
    reg_value_name: String,
    reg_type: String,
    final_reg_value: String,
}

/// # Create the GptTmpl.inf
/// `SCENoApplyLegacyAuditPolicy=1` makes the **advanced** audit policy (which we use) override the
/// basic audit policy settings (cf. description in `generate_audit_csv`).
/// It's the default but we enforce it to prevent unexpected settings
pub fn generate_gpt_tmpl_inf(
    registry_values: &[String],
    gpt_tmpl_inf_path: PathBuf,
    is_pdc: bool,
) -> anyhow::Result<()> {
    if !is_pdc {
        info!(
            "The current DC is not the PDC so it does not need to generate group policy settings"
        );
        return Ok(());
    }

    let mut content = "
[Unicode]
Unicode=yes
[Version]
signature=\"$CHICAGO$\"
Revision=1
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy=4,1
"
    .to_string();

    info!("Constructing GptTmpl.inf file content");

    let registry_values = registry_values.iter().collect::<HashSet<&String>>();
    for value in registry_values {
        content.push('\r');
        content.push('\n');
        content.push_str(value);
    }

    info!(
        "Write the content to {}:\r\n{content}",
        gpt_tmpl_inf_path.display()
    );
    let mut buffer = File::create(gpt_tmpl_inf_path)?;
    buffer.write_all(content.as_bytes())?;
    buffer.flush()?;

    Ok(())
}

pub fn subscribe_to_channels(
    callback: EVT_SUBSCRIBE_CALLBACK,
    current_build_number: Option<u32>,
    configuration_file_json: &EventsLogsConfiguration,
    subscribed_channels: &mut HashMap<String, isize>,
) {
    let channel_keys = if unsafe { PREVIEW } {
        let channel_keys = get_channel_keys();
        if let Err(ref err) = channel_keys {
            error!("An error occurred while trying to read the channel keys: {err}");
        }
        channel_keys
    } else {
        Err(anyhow::anyhow!("Preview mode has no channel keys"))
    };

    let channels = build_channels(&configuration_file_json.channels);
    for channel in channels {
        if let Ok(ref keys) = channel_keys {
            try_create_channel_key(&channel, keys);
        }

        let subscription_result = subscribe_to_channel(
            &configuration_file_json.events,
            &channel,
            callback,
            current_build_number,
        );

        if unsafe { !PREVIEW } {
            continue;
        }

        if let Ok(subscription_handle) = subscription_result {
            subscribed_channels.insert(channel, subscription_handle);
        }
    }
}

fn get_channel_keys() -> anyhow::Result<Vec<String>> {
    info!("Finding the channel registry keys...");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let event_logs_keys = hklm.open_subkey("SYSTEM\\CurrentControlSet\\Services\\EventLog\\")?;

    let keys: Vec<String> = event_logs_keys
        .enum_keys()
        .map(|k| k.unwrap_or(String::new()))
        .collect();

    Ok(keys)
}

fn try_create_channel_key(channel: &String, keys: &Vec<String>) {
    if is_default_channel(channel) {
        info!("Channel '{channel}' is a default channel so it doesn't need a registry key.");
        return;
    }

    let has_key = keys
        .iter()
        .find(|c| c.to_lowercase() == channel.to_lowercase())
        .is_some();

    if has_key {
        info!("Channel '{channel}' already has a registry key.");
        return;
    }

    info!("Channel '{channel}' does not have a registry key.");

    if let Err(err) = create_channel_key(channel) {
        error!("En error occurred while trying to create the key of channel '{channel}': {err}");
    }
}

fn create_channel_key(channel_name: &String) -> std::io::Result<()> {
    info!("Creating the registry key for channel '{channel_name}'...");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let event_logs_keys = hklm.open_subkey_with_flags(
        "SYSTEM\\CurrentControlSet\\Services\\EventLog\\",
        KEY_SET_VALUE,
    )?;

    event_logs_keys.create_subkey(channel_name)?;

    info!("The key for channel '{channel_name}' has been created");

    Ok(())
}

pub fn build_channels(additional_channels: &Vec<String>) -> Vec<String> {
    let mut channels = vec![];
    for channel_value in DEFAULT_CHANNELS {
        channels.push(channel_value.to_string());
    }
    for channel_value in additional_channels {
        if channel_value.is_empty() {
            continue;
        }

        channels.push(channel_value.clone());
    }

    channels
}

pub fn subscribe_to_channel(
    events: &Vec<EventLog>,
    channel: &String,
    callback: EVT_SUBSCRIBE_CALLBACK,
    current_build_number: Option<u32>,
) -> core::result::Result<isize, WIN32_ERROR> {
    match try_activate_and_refresh_channel_cache(channel, current_build_number) {
        Err(err) => error!(
            "An error occurred while refreshing the cache of the channel '{channel}': {err:?}"
        ),
        Ok(false) => info!("Channel '{channel}' did not need to be refreshed"),
        Ok(true) => info!("Channel '{channel}' was refreshed"),
    }

    let context = null_mut();

    // Query
    let query = build_xml_query(events, channel);

    let cloned_channel = channel.clone();
    let cloned_query = query.clone();

    unsafe {
        let h_subscription = EvtSubscribe(
            0,
            None,
            cloned_channel,
            cloned_query,
            0,
            context,
            callback,
            1,
        );

        let status = GetLastError();

        if h_subscription == 0 {
            if status == ERROR_EVT_CHANNEL_NOT_FOUND {
                error!("Channel {channel} was not found.");
            } else if status == ERROR_EVT_INVALID_QUERY {
                error!("Query {query} is not valid for {channel}.");
            } else {
                error!("EvtSubscribe failed for channel {channel}: ({status:?})");
            }
            Err(status)
        } else {
            info!("Successfully subscribed to {channel}.");
            Ok(h_subscription)
        }
    }
}

fn unsubscribe_all_channels(subscribed_channels: &HashMap<String, isize>) {
    for (channel, channel_handle) in subscribed_channels {
        info!("Unsubscribing from channel '{channel}'");
        let unsubscription_result = unsafe { EvtClose(*channel_handle) };

        if let Err(err) = unsubscription_result.ok() {
            error!("An error occurred while unsubscribing from channel '{channel}': {err:?}");
        } else {
            info!("Channel '{channel}' successfully unsubscribed");
        }
    }
}

pub fn log_configuration(configuration_file_content: String, args: &Arguments) {
    info!("Configuration set: {}", configuration_file_content);
    info!("Arguments provided: {:?}", args);
}

const RSOP_NS: &str = "http://www.microsoft.com/GroupPolicy/Rsop";
const SETTINGS_NS: &str = "http://www.microsoft.com/GroupPolicy/Settings";
const AUDITING_NS: &str = "http://www.microsoft.com/GroupPolicy/Settings/Auditing";

pub fn generate_audit_csv(
    audit: &Vec<String>,
    audit_folder: PathBuf,
    administrator_name: &str,
    is_pdc: bool,
) -> anyhow::Result<()> {
    if !is_pdc {
        info!("The current DC is not the PDC so it does not need to generate audit policies");
        return Ok(());
    }

    if !audit_folder.exists() {
        return Err(anyhow::anyhow!(
            "Audit folder {} does not exist",
            audit_folder.display()
        ));
    }

    let audit_csv_path = audit_folder.join("audit.csv");

    info!("Backup and remove auditpol CSE");
    let backup_gpc_machine_extension_names = get_powershell_output(
        "\
        $domainDn = Get-ADDomain | select -exp DistinguishedName;\
        $tenableGPO = Get-AdObject \
            -LDAPFilter \"(&(objectClass=groupPolicyContainer)(displayName=Tenable.ad))\" \
            -SearchBase \"CN=Policies,CN=System,$domainDn\" \
            -Properties gPCMachineExtensionNames;\
        $backupGPCMachineExtensionNames = $tenableGPO | select -exp gPCMachineExtensionNames;\
        $gPCMachineExtensionNamesNoAudit = $backupGPCMachineExtensionNames \
            -replace '\\[\\{F3CCC681-B74C-4060-9F26-CD84525DCA2A\\}\\{0F3F3735-573D-9804-99E4-AB2A69BA5FD4\\}\\]','';\
        Set-AdObject \
            -Identity $tenableGPO \
            -Replace @{gPCMachineExtensionNames=$gPCMachineExtensionNamesNoAudit};\
        $backupGPCMachineExtensionNames",
    )?;
    let backup_gpc_machine_extension_names = backup_gpc_machine_extension_names.trim();

    info!("Previous value of gPCMachineExtensionNames: {backup_gpc_machine_extension_names}");

    info!(
        "Generating {} on primary domain controller {}",
        audit_csv_path.display(),
        std::env::var("ComputerName")?
    );

    // We need to restore the CSEs in case of an error, most errors should be returned in the Result
    // but `catch_unwind` allows to catch a panic (except if it interrupts the program immediately)
    // See https://doc.rust-lang.org/std/panic/fn.catch_unwind.html#notes
    let result = std::panic::catch_unwind(|| {
        generate_audit_csv_file(audit, audit_csv_path, administrator_name)
    });

    info!("Restore auditpol CSE");
    let _ = get_powershell_output(format!(
        "\
        $domainDn = Get-ADDomain | select -exp DistinguishedName;\
        $tenableGPO = Get-AdObject \
            -LDAPFilter \"(&(objectClass=groupPolicyContainer)(displayName=Tenable.ad))\" \
            -SearchBase \"CN=Policies,CN=System,$domainDn\" \
            -Properties gPCMachineExtensionNames;\
        $backupGPCMachineExtensionNames = \"{backup_gpc_machine_extension_names}\";\
        Set-AdObject \
            -Identity $tenableGPO \
            -Replace @{{gPCMachineExtensionNames=$backupGPCMachineExtensionNames}}"
    ))?;

    match result {
        Ok(result) => result,
        Err(panic) => Err(anyhow::anyhow!("A panic occurred: {panic:?}!")),
    }
}

/// This function generates an audit.csv file to backport custom audit policies (both already
/// existing and ours)
///
/// # Basic vs Advanced
/// audit.csv is stored in the GPO SYSVOL folder and is read by the "audit policy configuration"
/// CSE, it's the native format generated when editing **advanced** audit policy in the GPO editor
/// in Windows there are two sets of audit policy settings, basic (9 top-level categories in "audit
/// policy") and **advanced** (53 sub-level categories in 10 categories) we want to use
/// **advanced** through audit.csv added to our GPO, because it allows a more granular
/// configuration the CSE properly handles when several GPOs define **advanced** audit policies
/// through precedence and merging.
/// Warning: GPO priority matters in merging. For example, if a first GPO, with a higher priority,
/// enables "Success" logging, and a second GPO, with a lower priority, enables "Success and
/// Failure" logging, then only "Success" will be logged!
/// Given that the Tenable.ad GPO will have an higher priority ("enforced" is checked), we ensure
/// that we do not mask a setting required by a lower priority GPO, see in code below.
///
/// # RSoP output generation as SYSTEM user
/// This executable runs as SYSTEM, and in some cases, gpresult fails if we don't specify a user
/// (even though we only request RSoP for the computer scope...) so we retry while giving to
/// gpresult a user that can authenticate locally on a domain controller to simulate the RSoP. The
/// builtin RID 500 admin is used.
///
/// # audit.csv single generation
/// The primary domain controller in the domain will generate the audit.csv file then it will be
/// replicated to other domain controllers.
///
/// # Audit Policy Configuration CSE
/// The GPO needs to have the "Audit Policy Configuration" CSE in its attribute "gPCMachineExtensionNames"
/// but we have to remove it when retrieving the audit policies of the other GPOs and reapply it after
/// having modified our audit.csv file (otherwise we would generate it based on the values defined inside
/// our own GPO, which would make our calculations wrong).
fn generate_audit_csv_file(
    audit: &Vec<String>,
    output_path: PathBuf,
    administrator_name: &str,
) -> anyhow::Result<()> {
    run_command("gpupdate /force")?;

    let temporary_task_folder = tempfile::tempdir()?;
    let temporary_task_folder_path = temporary_task_folder.path().display().to_string();

    info!("Temporary folder {temporary_task_folder_path} created");

    // Create the audit.csv with Tenable.ad required logging settings
    let mut audit_csv = String::from("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n");
    for audit in audit {
        audit_csv.push_str(&audit);
        audit_csv.push('\r');
        audit_csv.push('\n');
    }

    let audit_csv = get_audit_csv_data(audit_csv)?;

    let gpresult_xml = get_gpresult_xml(&temporary_task_folder, administrator_name)?;

    let adv_audit_policies = get_adv_audit_policies(&gpresult_xml).unwrap_or(vec![]);

    info!("Advanced audit policies extracted from generated file");

    let gpresult = adv_audit_policies
        .iter()
        .filter(|n| n.is("AuditSetting", AUDITING_NS))
        .map(|audit_setting| AuditSetting {
            subcategory_guid: audit_setting
                .get_child("SubcategoryGuid", AUDITING_NS)
                .map(|n| n.text().to_lowercase())
                .unwrap_or(String::new()),
            // subcategory_name: audit_setting
            //     .get_child("SubcategoryName", AUDITING_NS)
            //     .map(|n| n.text())
            //     .unwrap_or(String::new()),
            setting_value: audit_setting
                .get_child("SettingValue", AUDITING_NS)
                .map(|n| n.text().parse().unwrap_or(0))
                .unwrap_or(0),
        })
        .collect::<Vec<AuditSetting>>();

    info!("RSoP extracted from generated file");

    let audit_csv_temp_file_path = temporary_task_folder.path().join("audit.csv");
    let audit_csv_temp_file_path_name = audit_csv_temp_file_path.to_string_lossy();

    run_command(format!(
        "auditpol.exe /backup /file:\"{audit_csv_temp_file_path_name}\""
    ))?;

    info!("Auditpol outpout generated at {audit_csv_temp_file_path_name}");

    let auditpol = read_as_utf8_string(audit_csv_temp_file_path)?;
    let auditpol = get_audit_csv_data(auditpol)?;

    info!("Auditpol output extracted and converted");

    let mut new_audit_csv = vec![];
    for audit_config in audit_csv.iter() {
        let sub_guid = audit_config.subcategory_guid.clone();
        let sub_name = audit_config.subcategory.clone();

        let auditpol_value = match auditpol.iter().find(|a| a.subcategory_guid == sub_guid) {
            Some(v) => v,
            None => {
                info!("No value found in auditpol output for {sub_name} ({sub_guid})");
                new_audit_csv.push(audit_config.clone());
                continue;
            }
        };

        // Checking if there is currently a setting that blocks something we need
        if auditpol_value.setting_value == Some(0) || auditpol_value.setting_value == Some(4) {
            let gpresult_value = match gpresult.iter().find(|r| r.subcategory_guid == sub_guid) {
                Some(v) => v,
                None => {
                    info!("No value found in RSoP output for {sub_name} ({sub_guid})");
                    new_audit_csv.push(audit_config.clone());
                    continue;
                }
            };
            if gpresult_value.setting_value == 0 || gpresult_value.setting_value == 4 {
                return Err(anyhow::anyhow!(format!(
                    "Tenable.ad requires the audit policy {sub_name} \
                    but the current AD configuration prevents its usage"
                )));
            }
        }

        // TODO: The fix below should be applied once the current behavior is validated
        // if auditpol_value.setting_value == Some(0) || auditpol_value.setting_value == Some(4) {
        //     info!("Value found in auditpol output can be overriden for {sub_name} ({sub_guid})");
        //     new_audit_csv.push(audit_config.clone());
        //     continue;
        // }

        if auditpol_value.setting_value == audit_config.setting_value {
            info!("Value found in auditpol output is the one needed for {sub_name} ({sub_guid})");
            new_audit_csv.push(audit_config.clone());
            continue;
        }

        info!(
            "Setting value found in auditpol output to Success and Failure \
            for {sub_name} ({sub_guid})"
        );
        let mut audit_config = audit_config.clone();
        // TODO: The fix below should be applied once the current behavior is validated
        // audit_config.inclusion_setting = String::from("Success and Failure");
        audit_config.setting_value = Some(3);
        new_audit_csv.push(audit_config);
    }

    // Converting existing basic configuration (not needed) to advanced one
    if adv_audit_policies.len() == 0 {
        info!("Trying to convert existing basic audit policies to advanced ones");
        let mut basic_audit_policies_to_migrate = vec![];
        for audit_policies_sub_category in auditpol {
            if audit_policies_sub_category.subcategory_guid != ""
                && !(audit_policies_sub_category.setting_value == Some(0)
                    || audit_policies_sub_category.setting_value == Some(4))
            {
                let guid = audit_policies_sub_category.subcategory_guid;
                let name = audit_policies_sub_category.subcategory;
                let value = audit_policies_sub_category.setting_value;
                let not_needed_rsop_value = audit_csv.iter().find(|a| a.subcategory_guid == guid);
                if let None = not_needed_rsop_value {
                    info!(
                        "Existing audit policy {name} ({guid}) value will be set to {value:?} \
                        like previously"
                    );
                    let new_basic_setting = AuditCsvLine {
                        machine_name: audit_policies_sub_category.machine_name,
                        policy_target: audit_policies_sub_category.policy_target,
                        subcategory: format!("Audit {name}"),
                        subcategory_guid: guid,
                        inclusion_setting: audit_policies_sub_category.inclusion_setting,
                        exclusion_setting: audit_policies_sub_category.exclusion_setting,
                        setting_value: value,
                    };
                    basic_audit_policies_to_migrate.push(new_basic_setting);
                }
            }
        }
        new_audit_csv.append(&mut basic_audit_policies_to_migrate);
    }

    let mut writer = csv::Writer::from_path(&output_path)?;
    for audit_line in new_audit_csv {
        writer.serialize(audit_line)?;
    }
    writer.flush()?;

    info!("Generated audit policies on file {}", output_path.display());

    drop(temporary_task_folder);

    info!("Temporary folder {temporary_task_folder_path} cleaned");

    Ok(())
}

#[derive(Debug)]
struct AuditSetting {
    subcategory_guid: String,
    // subcategory_name: String, // Not used so we comment it to avoid a warning
    setting_value: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AuditCsvLine {
    #[serde(rename = "Machine Name")]
    machine_name: String,
    #[serde(rename = "Policy Target")]
    policy_target: String,
    #[serde(rename = "Subcategory")]
    subcategory: String,
    #[serde(rename = "Subcategory GUID", deserialize_with = "to_lowercase")]
    subcategory_guid: String,
    #[serde(rename = "Inclusion Setting")]
    inclusion_setting: String,
    #[serde(rename = "Exclusion Setting")]
    exclusion_setting: String,
    #[serde(rename = "Setting Value")]
    setting_value: Option<u8>,
}

fn to_lowercase<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    Ok(s.to_lowercase())
}

fn get_audit_csv_data(audit_csv: String) -> anyhow::Result<Vec<AuditCsvLine>> {
    info!("Parsing audit CSV data:\r\n{audit_csv}");
    let mut result = vec![];
    let mut reader = csv::Reader::from_reader(audit_csv.as_bytes());
    for line in reader.deserialize() {
        let line = line?;
        result.push(line);
    }
    Ok(result)
}

pub fn run_command<S>(command: S) -> anyhow::Result<()>
where
    S: AsRef<OsStr>,
    S: std::fmt::Display,
{
    info!("Running command '{command}'");

    let output = std::process::Command::new("PowerShell")
        .arg(command)
        .output()?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(error.to_string()));
    }

    Ok(())
}

fn read_as_utf8_string(path: PathBuf) -> std::io::Result<String> {
    info!("Read file at path '{}'", path.display());
    let file = File::open(path)?;

    info!("Decode file to utf-8");
    let mut decoder = encoding_rs_io::DecodeReaderBytes::new(file);
    let mut content = String::new();
    decoder.read_to_string(&mut content)?;

    Ok(content)
}

fn get_gpresult_xml(
    temporary_task_folder: &TempDir,
    administrator_name: &str,
) -> anyhow::Result<Element> {
    let rsop_file_path = temporary_task_folder.path().join("rsop.xml");
    let rsop_file_path_name = rsop_file_path.to_string_lossy();

    info!("Generating RSoP file at {rsop_file_path_name}");

    run_command(format!(
        "gpresult.exe /SCOPE COMPUTER /X {rsop_file_path_name}"
    ))?;

    if !rsop_file_path.exists() {
        info!("Generating RSoP file at {rsop_file_path_name} failed");
        info!("Generating RSoP file at {rsop_file_path_name} for {administrator_name}");
        run_command(format!(
            "gpresult.exe /SCOPE COMPUTER /X {rsop_file_path_name} /USER {administrator_name}"
        ))?;

        if !rsop_file_path.exists() {
            info!("RSoP file was not generated");
            return Err(anyhow::anyhow!("RSoP file generation failed"));
        }
    }

    info!("RSoP file generated at {rsop_file_path_name}");

    let mut rsop = read_as_utf8_string(rsop_file_path)?;

    // Removes the encoding header otherwise minidom refuses to parse it:
    // RestrictedXml("only utf-8 encoding is allowed")
    // (although the file content has been converted to utf-8)
    if rsop.starts_with("<?xml ") {
        let newline_index = rsop
            .char_indices()
            .find(|(_, c)| *c == '\r' || *c == '\n')
            .map_or(0, |(i, _)| i);
        rsop = String::from(&rsop[newline_index..]).trim_start().to_owned();
    };

    let xml = match rsop.parse::<Element>() {
        Ok(xml) => xml,
        Err(err) => {
            warn!("The content of the RSoP file seems to be faulty:");
            warn!("{rsop}");
            return Err(err)?;
        }
    };

    if !xml.is("Rsop", RSOP_NS) {
        return Err(anyhow::anyhow!("Tag 'Rsop' is missing"));
    }

    Ok(xml)
}

fn get_adv_audit_policies(gpresult_xml: &Element) -> Option<Vec<&Element>> {
    let adv_audit_policies = gpresult_xml
        .get_child("ComputerResults", NSChoice::Any)?
        .children()
        .filter(|n| n.is("ExtensionData", NSChoice::Any))
        .find(|n| {
            n.get_child("Name", SETTINGS_NS).map(|c| c.text())
                == Some(String::from("Advanced Audit Configuration"))
        })?
        .get_child("Extension", SETTINGS_NS)?
        .children()
        .collect();

    Some(adv_audit_policies)
}

fn get_powershell_output<S>(command: S) -> anyhow::Result<String>
where
    S: AsRef<OsStr>,
    S: std::fmt::Display,
{
    info!("Run powershell command:\r\n{command}");

    let output = std::process::Command::new("PowerShell")
        .arg(command)
        .output()?;

    if !output.status.success() {
        let error = String::from_utf8(output.stderr)?;
        return Err(anyhow::anyhow!(error));
    }

    let stdout = String::from_utf8(output.stdout)?;

    info!("Output of the command:\r\n{stdout}");

    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use windows::Win32::System::EventLog::EVT_SUBSCRIBE_NOTIFY_ACTION;

    unsafe extern "system" fn empty_callback(
        _: EVT_SUBSCRIBE_NOTIFY_ACTION,
        _: *const c_void,
        _: isize,
    ) -> u32 {
        0
    }

    mod handle_file_changes {
        use super::empty_callback;
        use crate::{
            setup::{handle_file_changes, FileChanged},
            Arguments, EventLog, EventsLogsConfiguration, PREVIEW,
        };
        use std::{collections::HashMap, io::Write, num::NonZeroU8};
        use windows::Win32::System::EventLog::EVT_SUBSCRIBE_CALLBACK;

        const raw_configuration_file_content: &[u8] = br#"{
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

        #[test]
        fn with_empty_subscribed_channel_handles_should_feed_with_default_and_resquested_channels()
        {
            // Arrange
            unsafe { PREVIEW = true };

            // Create a temporary file for test config.
            let mut tmp_file = tempfile::NamedTempFile::new()
                .expect("Unable to create temporary file for the test.");
            tmp_file
                .as_file_mut()
                .write_all(raw_configuration_file_content)
                .expect("Unable to write in a temporary file for the test.");

            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();
            let args = Arguments {
                event_log_file_path: "./EventLogs.gz".to_string(),
                timer_duration_seconds: 15,
                max_buffer_size_bytes: 524288000,
                max_throughput: 1500,
                duration_leap: 10,
                enable_gzip: true,
                cpu_rate: NonZeroU8::new(20).unwrap(),
                preview: true,
                audit_folder: "".into(),
                administrator_name: "".into(),
                pdc_name: "".into(),
                domain_name: "".into(),
                domain_controller_dns_name: "".into(),
                gpt_tmpl_file: "".into(),
                registry_pol_file: "".into(),
                conf_interval_in_minutes: NonZeroU8::new(5).unwrap(),
            };
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let current_build_number = Some(42);
            let mut current_configuration = EventsLogsConfiguration {
                events: vec![],
                channels: vec![],
                audit: vec![],
                registry_values: vec![],
                pol_values: vec![],
            };

            // Act
            handle_file_changes(
                tmp_file.path(),
                &mut subscribed_channels,
                &args,
                callback,
                current_build_number,
                &mut current_configuration,
                FileChanged::ConfigurationChanged,
                true,
            );

            // Assert
            assert_eq!(subscribed_channels.len(), 4);
            assert!(subscribed_channels.contains_key("Security"));
            assert!(subscribed_channels.contains_key("System"));
            assert!(subscribed_channels.contains_key("Application"));
            assert!(subscribed_channels.contains_key("Setup"));
        }

        #[test]
        fn with_populated_subscribed_channel_handles_should_clear_then_feed_with_default_and_resquested_channels(
        ) {
            // Arrange
            unsafe { PREVIEW = true };

            // Create a temporary file for test config.
            let mut tmp_file = tempfile::NamedTempFile::new()
                .expect("Unable to create temporary file for the test.");
            tmp_file
                .as_file_mut()
                .write_all(raw_configuration_file_content)
                .expect("Unable to write in a temporary file for the test.");

            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();
            subscribed_channels.insert("ChannelName0".to_string(), 42);
            subscribed_channels.insert("ChannelName1".to_string(), 21);
            let args = Arguments {
                event_log_file_path: "./EventLogs.gz".to_string(),
                timer_duration_seconds: 15,
                max_buffer_size_bytes: 524288000,
                max_throughput: 1500,
                duration_leap: 10,
                enable_gzip: true,
                cpu_rate: NonZeroU8::new(20).unwrap(),
                preview: true,
                audit_folder: "".into(),
                administrator_name: "".into(),
                pdc_name: "".into(),
                domain_name: "".into(),
                domain_controller_dns_name: "".into(),
                gpt_tmpl_file: "".into(),
                registry_pol_file: "".into(),
                conf_interval_in_minutes: NonZeroU8::new(5).unwrap(),
            };
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let current_build_number = Some(42);
            let mut current_configuration = EventsLogsConfiguration {
                events: vec![],
                channels: vec![],
                audit: vec![],
                registry_values: vec![],
                pol_values: vec![],
            };

            // Act
            handle_file_changes(
                tmp_file.path(),
                &mut subscribed_channels,
                &args,
                callback,
                current_build_number,
                &mut current_configuration,
                FileChanged::ConfigurationChanged,
                true,
            );

            // Assert
            assert_eq!(subscribed_channels.len(), 4);
            assert!(subscribed_channels.contains_key("Security"));
            assert!(subscribed_channels.contains_key("System"));
            assert!(subscribed_channels.contains_key("Application"));
            assert!(subscribed_channels.contains_key("Setup"));
        }

        #[test]
        fn when_new_config_is_equivalent_to_current_should_discard_and_do_nothing() {
            // Arrange
            unsafe { PREVIEW = true };

            // Create a temporary file for test config.
            let mut tmp_file = tempfile::NamedTempFile::new()
                .expect("Unable to create temporary file for the test.");
            tmp_file
                .as_file_mut()
                .write_all(raw_configuration_file_content)
                .expect("Unable to write in a temporary file for the test.");

            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();

            // Insert some channels' names to ensure that the HashMap remains untouched.
            subscribed_channels.insert("ChannelName0".to_string(), 42);
            subscribed_channels.insert("ChannelName1".to_string(), 21);

            let args = Arguments {
                event_log_file_path: "./EventLogs.gz".to_string(),
                timer_duration_seconds: 15,
                max_buffer_size_bytes: 524288000,
                max_throughput: 1500,
                duration_leap: 10,
                enable_gzip: true,
                cpu_rate: NonZeroU8::new(20).unwrap(),
                preview: true,
                audit_folder: "".into(),
                administrator_name: "".into(),
                pdc_name: "".into(),
                domain_name: "".into(),
                domain_controller_dns_name: "".into(),
                gpt_tmpl_file: "".into(),
                registry_pol_file: "".into(),
                conf_interval_in_minutes: NonZeroU8::new(5).unwrap(),
            };
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let current_build_number = Some(42);
            let mut current_configuration = EventsLogsConfiguration {
                events: vec![
                    EventLog {
                        id: 541,
                        provider_name: "Microsoft-Windows-DNSServer".to_string(),
                    },
                    EventLog {
                        id: 4624,
                        provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                    },
                ],
                channels: vec!["Setup".to_string()],
                audit: vec![],
                registry_values: vec![],
                pol_values: vec![],
            };

            // Act
            handle_file_changes(
                tmp_file.path(),
                &mut subscribed_channels,
                &args,
                callback,
                current_build_number,
                &mut current_configuration,
                FileChanged::ConfigurationChanged,
                true,
            );

            // Assert
            // Assert that the HashMap has not been cleared nor fed.
            assert_eq!(subscribed_channels.len(), 2);
            assert!(subscribed_channels.contains_key("ChannelName0"));
            assert!(subscribed_channels.contains_key("ChannelName1"));
        }

        #[test]
        fn when_new_config_is_different_from_current_should_apply_it_and_store_new_config() {
            // Arrange
            unsafe { PREVIEW = true };

            // Create a temporary file for test config.
            let mut tmp_file = tempfile::NamedTempFile::new()
                .expect("Unable to create temporary file for the test.");
            tmp_file
                .as_file_mut()
                .write_all(raw_configuration_file_content)
                .expect("Unable to write in a temporary file for the test.");

            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();

            let args = Arguments {
                event_log_file_path: "./EventLogs.gz".to_string(),
                timer_duration_seconds: 15,
                max_buffer_size_bytes: 524288000,
                max_throughput: 1500,
                duration_leap: 10,
                enable_gzip: true,
                cpu_rate: NonZeroU8::new(20).unwrap(),
                preview: true,
                audit_folder: "".into(),
                administrator_name: "".into(),
                pdc_name: "".into(),
                domain_name: "".into(),
                domain_controller_dns_name: "".into(),
                gpt_tmpl_file: "".into(),
                registry_pol_file: "".into(),
                conf_interval_in_minutes: NonZeroU8::new(5).unwrap(),
            };
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let current_build_number = Some(42);
            let mut current_configuration = EventsLogsConfiguration {
                events: vec![],
                channels: vec![],
                audit: vec![],
                registry_values: vec![],
                pol_values: vec![],
            };
            let expected_configuration = EventsLogsConfiguration {
                events: vec![
                    EventLog {
                        id: 541,
                        provider_name: "Microsoft-Windows-DNSServer".to_string(),
                    },
                    EventLog {
                        id: 4624,
                        provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                    },
                ],
                channels: vec!["Setup".to_string()],
                audit: vec![],
                registry_values: vec![],
                pol_values: vec![],
            };

            // Act
            handle_file_changes(
                tmp_file.path(),
                &mut subscribed_channels,
                &args,
                callback,
                current_build_number,
                &mut current_configuration,
                FileChanged::ConfigurationChanged,
                true,
            );

            // Assert
            assert_eq!(subscribed_channels.len(), 4);
            assert!(subscribed_channels.contains_key("Security"));
            assert!(subscribed_channels.contains_key("System"));
            assert!(subscribed_channels.contains_key("Application"));
            assert!(subscribed_channels.contains_key("Setup"));
            assert!(current_configuration == expected_configuration);
        }
    }

    mod get_registry_policy {
        use super::super::*;

        #[test]
        fn returns_valid_data() {
            assert_eq!(
                get_registry_policy(&String::from(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\\
                     Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled=4,1"
                )),
                Some(RegistryPolicy {
                    reg_path: String::from(
                        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\\
                         Policies\\System\\Audit"
                    ),
                    reg_value_name: String::from("ProcessCreationIncludeCmdLine_Enabled"),
                    reg_type: String::from("4"),
                    final_reg_value: String::from("1"),
                })
            );
        }

        #[test]
        fn returns_valid_data_with_a_string() {
            assert_eq!(
                get_registry_policy(&String::from(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\\
                     Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled=1,\"This, is \
                     a = long \\ string \r\n with special * characters \""
                )),
                Some(RegistryPolicy {
                    reg_path: String::from(
                        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\\
                         Policies\\System\\Audit"
                    ),
                    reg_value_name: String::from("ProcessCreationIncludeCmdLine_Enabled"),
                    reg_type: String::from("1"),
                    final_reg_value: String::from(
                        "\"This, is a = long \\ string \r\n with special * characters \""
                    ),
                })
            );
        }
    }

    mod generate_audit_csv {
        #[test]
        fn it_should_parse_the_rsop_xml_file() {
            let rsop_xml = include_str!("../data/rsop.xml");
            let result = rsop_xml.parse::<minidom::Element>();
            assert!(result.is_ok());
        }
    }
}
