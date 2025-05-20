use super::constants::*;
use crate::configuration::{Arguments, EventsLogsConfiguration};
use crate::powershell::{
    force_gpo_update, get_powershell_output_lossy, get_powershell_unicode_output,
};
use crate::sharing::file_sharing_manager::FileSharingManager;
use crate::{
    build_xml_query,
    channel::{is_default_channel, try_activate_and_refresh_channel_cache, DEFAULT_CHANNELS},
    EventLog, PREVIEW,
};
use csv::{Terminator, WriterBuilder};
use log::{error, info, warn};
use minidom::{Element, NSChoice};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::{Arc, Mutex};
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_void, OsStr},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    ptr::null_mut,
    slice::from_raw_parts,
};
use tempfile::TempDir;
use uuid::Uuid;
use windows::core::GUID;
use windows::Win32::{
    Foundation::{
        GetLastError, BOOLEAN, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_QUERY, WIN32_ERROR,
    },
    Security::Authentication::Identity::{
        AuditEnumerateCategories, AuditEnumerateSubCategories, AuditFree, AuditQuerySystemPolicy,
        AUDIT_POLICY_INFORMATION,
    },
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

pub fn handle_file_changes(
    file_sharing_manager: &Arc<Mutex<FileSharingManager>>,
    path: &Path,
    subscribed_channels: &mut HashMap<String, isize>,
    args: &Arguments,
    callback: EVT_SUBSCRIBE_CALLBACK,
    current_build_number: Option<u32>,
    current_configuration: &mut EventsLogsConfiguration,
    file_changed: FileChanged,
    is_pdc: bool,
) {
    let (configuration_file_json, configuration_file_content) =
        match EventsLogsConfiguration::read_setup_from_file(path) {
            Ok(result) => result,
            Err(err) => {
                // TODO: Add a retry mechanism?
                error!("An error occurred while reading the setup file: {err}");
                return;
            }
        };

    // Ensure that the current and new configuration are different before trying to do anything.
    match file_changed {
        FileChanged::ConfigurationChanged => {
            if *current_configuration == configuration_file_json {
                info!("The previously applied configuration and the new one are equivalent, ignoring the new configuration");
                return;
            }

            log_configuration(configuration_file_content, args);
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

            if let Err(err) = force_gpo_update() {
                error!("An error occurred while trying to force the GP update: {err}");
            }

            subscribe_to_channels(
                callback,
                current_build_number,
                &configuration_file_json,
                subscribed_channels,
            );

            // Here we use a block to limit the lifetime of the lock guard.
            {
                let mut curr_file_sharing_manager = file_sharing_manager.lock().unwrap();
                let _ = curr_file_sharing_manager
                    .on_configuration_change(is_pdc, &configuration_file_json)
                    .map_err(|e| error!("An error occurred while trying to live update the file sharing implementation: {:?}", e));
            }

            *current_configuration = configuration_file_json;

            // Change the sync file to tell other DCs that they can resubscribe
            update_sync_file();
        }
        // When any file other than the configuration file is modified, we only want to update our subscriptions to the channels.
        _ => {
            unsubscribe_all_channels(subscribed_channels);

            subscribed_channels.clear();

            if let Err(err) = force_gpo_update() {
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
        Ok(content) => content.first().copied().unwrap_or(0),
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

fn extract_gpo_guid_from_path(path: &str) -> Option<String> {
    path.split("\\Policies\\{")
        .nth(1)?
        .split('}')
        .next()
        .map(|s| s.to_string())
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

    let gpo_guid_option = extract_gpo_guid_from_path(registry_pol_file);
    let registry_pol_file: PathBuf = registry_pol_file.into();

    let gpo_guid = match gpo_guid_option {
        None => {
            return Err(anyhow::anyhow!(
                "Cannot extrat GPO Guid from Regirstry pol file path {}",
                registry_pol_file.display()
            ));
        }
        Some(guid) => guid,
    };

    info!("Extracted GPO Guid => {}", gpo_guid);

    if registry_pol_file.exists() {
        if let Err(err) = std::fs::remove_file(&registry_pol_file) {
            return Err(anyhow::anyhow!(
                "An error occurred while trying to remove file at {}: {}",
                registry_pol_file.display(),
                err
            ));
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
            get_powershell_output_lossy(format!(
                "Import-Module GroupPolicy; Set-GPRegistryValue \
                    -Guid '{gpo_guid}' \
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
    let channel_keys = get_channel_keys();
    if let Err(ref err) = channel_keys {
        error!("An error occurred while trying to read the channel keys: {err}");
    }

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
        .any(|c| c.to_lowercase() == channel.to_lowercase());

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
const AUDIT_KEY: &str =
    "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";
const LDAP_FILTER: &str = "(&(objectclass=groupPolicyContainer)(!(isDeleted=TRUE))(|(displayName=Tenable.ad)(description=This GPO has been created as part of the deployment of Tenable Identity Exposure. Do not edit.)))";
const BACKUP_AUDIT_COMMAND: &str = "\
        $domainDn = Get-ADDomain | select -exp DistinguishedName;\
        $tenableGPO = Get-AdObject \
            -LDAPFilter \"__LDAP_FILTER__\" \
            -SearchBase \"CN=Policies,CN=System,$domainDn\" \
            -Properties gPCMachineExtensionNames;\
        $backupGPCMachineExtensionNames = $tenableGPO | select -exp gPCMachineExtensionNames;\
        $gPCMachineExtensionNamesNoAudit = $backupGPCMachineExtensionNames -replace '__AUDIT_KEY__','';\
        Set-AdObject \
            -Identity $tenableGPO \
            -Replace @{gPCMachineExtensionNames=$gPCMachineExtensionNamesNoAudit};\
        $backupGPCMachineExtensionNames";

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
            "Audit folder '{}' does not exist",
            audit_folder.display()
        ));
    }

    let audit_csv_path = audit_folder.join("audit.csv");

    info!("Backup and remove auditpol CSE");

    let backup_audit_command: String = BACKUP_AUDIT_COMMAND
        .replace("__AUDIT_KEY__", AUDIT_KEY)
        .replace("__LDAP_FILTER__", LDAP_FILTER);

    let backup_gPCMachineExtensionNames: String =
        get_powershell_unicode_output(backup_audit_command)?
            .trim()
            .to_string();

    info!("Current value of gPCMachineExtensionNames: {backup_gPCMachineExtensionNames}");

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

    match result {
        Ok(result) => {
            let patched_gPCMachineExtensionNames = get_patched_gPCMachineExtensionNames(
                &backup_gPCMachineExtensionNames,
                result.is_ok(),
            );
            let _ = patch_gPCMachineExtensionNames(&patched_gPCMachineExtensionNames)?;
            result
        }
        Err(panic) => {
            let patched_gPCMachineExtensionNames =
                get_patched_gPCMachineExtensionNames(&backup_gPCMachineExtensionNames, false);
            let _ = patch_gPCMachineExtensionNames(&patched_gPCMachineExtensionNames)?;
            Err(anyhow::anyhow!("A panic occurred: {panic:?}!"))
        }
    }
}

fn get_patched_gPCMachineExtensionNames(
    gPCMachineExtensionNames: &String,
    auditCsvGenerationOk: bool,
) -> String {
    if !auditCsvGenerationOk {
        warn!("Audit CSV generation failed, removing audit key from GPO gPCMachineExtensionNames");
        return gPCMachineExtensionNames.replace(AUDIT_KEY, "");
    }

    // Audit CSV genereation is OK

    // Check if Audit key are contained in gPCMachineExtensionNames
    if !gPCMachineExtensionNames.contains(AUDIT_KEY) {
        // We need to restore audit key or the Advanced Audit policies will not be applied anymore
        let patchedbackupGPCMachineExtensionNames =
            sort_gPCMachineExtensionNames(&format!("{}{}", gPCMachineExtensionNames, AUDIT_KEY));
        info!("Adding missing audit key value to gPCMachineExtensionNames");
        patchedbackupGPCMachineExtensionNames
    } else {
        gPCMachineExtensionNames.to_string()
    }
}

fn sort_gPCMachineExtensionNames(input: &str) -> String {
    let mut pairs = Vec::new();
    let mut i = 0;

    while let Some(start) = input[i..].find("[{") {
        let abs_start = i + start;
        if let Some(end) = input[abs_start..].find("}]") {
            let abs_end = abs_start + end + 2; // include "}]"
            pairs.push(&input[abs_start..abs_end]);
            i = abs_end;
        } else {
            break;
        }
    }

    pairs.sort_by_key(|pair| pair[2..38].to_uppercase());
    pairs.concat()
}

fn patch_gPCMachineExtensionNames(
    backupGPCMachineExtensionNames: &String,
) -> anyhow::Result<String> {
    info!("Restoring auditpol CSE: {backupGPCMachineExtensionNames}");
    get_powershell_output_lossy(format!(
        "\
        $domainDn = Get-ADDomain | select -exp DistinguishedName;\
        $tenableGPO = Get-AdObject \
            -LDAPFilter \"{LDAP_FILTER}\" \
            -SearchBase \"CN=Policies,CN=System,$domainDn\" \
            -Properties gPCMachineExtensionNames;\
        $backupGPCMachineExtensionNames = \"{backupGPCMachineExtensionNames}\";\
        $null = Set-AdObject \
            -Identity $tenableGPO \
            -Replace @{{gPCMachineExtensionNames=$backupGPCMachineExtensionNames}}"
    ))
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
    force_gpo_update()?;

    let temporary_task_folder = tempfile::tempdir()?;
    let temporary_task_folder_path = temporary_task_folder.path().display().to_string();

    info!("Temporary folder {temporary_task_folder_path} created");

    // Create the audit.csv with Tenable.ad required logging settings
    let mut audit_csv = String::from("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n");
    for audit in audit {
        audit_csv.push_str(audit);
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

    let auditpol: Vec<AuditCsvLine>;

    match unsafe { PREVIEW } {
        true => {
            info!("Current applied subcategories audit policies generated with Windows APIs");

            auditpol = get_current_applied_audit_policies()?;

            info!("Current applied subcategories audit policies extracted");
        }
        false => {
            info!("Current applied subcategories audit policies generated with auditpol");

            let audit_csv_temp_file_path = temporary_task_folder.path().join("audit.csv");
            let audit_csv_temp_file_path_name = audit_csv_temp_file_path.to_string_lossy();

            run_command(format!(
                "auditpol.exe /backup /file:\"{audit_csv_temp_file_path_name}\""
            ))?;

            info!("Auditpol outpout generated at {audit_csv_temp_file_path_name}");

            let auditpol_string = read_as_utf8_string(audit_csv_temp_file_path)?;
            auditpol = get_audit_csv_data(auditpol_string)?;

            info!("Auditpol output extracted and converted");
        }
    }

    let mut new_audit_csv = vec![];
    for audit_config in audit_csv.iter() {
        let sub_guid = audit_config.subcategory_guid.clone();
        let sub_name = audit_config.subcategory.clone();

        let auditpol_value = match auditpol.iter().find(|a| a.subcategory_guid == sub_guid) {
            Some(v) => v,
            None => {
                info!(
                    "No value found in current audit policies output for {sub_name} ({sub_guid})"
                );
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
                    "Tenable Identity Exposure requires the audit policy {sub_name} \
                    but the current AD configuration prevents its usage"
                )));
            }
        }

        // TODO: The fix below should be applied once the current behavior is validated
        // if auditpol_value.setting_value == Some(0) || auditpol_value.setting_value == Some(4) {
        //     info!("Value found in current audit policies output can be overriden for {sub_name} ({sub_guid})");
        //     new_audit_csv.push(audit_config.clone());
        //     continue;
        // }

        if auditpol_value.setting_value == audit_config.setting_value {
            info!("Value found in current audit policies output is the one needed for {sub_name} ({sub_guid})");
            new_audit_csv.push(audit_config.clone());
            continue;
        }

        info!(
            "Setting value found in current audit policies output to Success and Failure \
            for {sub_name} ({sub_guid})"
        );
        let mut audit_config = audit_config.clone();
        // TODO: The fix below should be applied once the current behavior is validated
        // audit_config.inclusion_setting = String::from("Success and Failure");
        audit_config.setting_value = Some(3);
        new_audit_csv.push(audit_config);
    }

    // Converting existing basic configuration (not needed) to advanced one
    if adv_audit_policies.is_empty() {
        info!("Trying to convert existing basic audit policies to advanced ones");
        let mut basic_audit_policies_to_migrate = vec![];
        for audit_policies_sub_category in auditpol {
            if !audit_policies_sub_category.subcategory_guid.is_empty()
                && !(audit_policies_sub_category.setting_value == Some(0)
                    || audit_policies_sub_category.setting_value == Some(4))
            {
                let guid = audit_policies_sub_category.subcategory_guid;
                let name = audit_policies_sub_category.subcategory;
                let value = audit_policies_sub_category.setting_value;
                let not_needed_rsop_value = audit_csv.iter().find(|a| a.subcategory_guid == guid);
                if not_needed_rsop_value.is_none() {
                    info!(
                        "Existing audit policy {} ({}) value will be set to {} like previously",
                        name,
                        guid,
                        value.unwrap() // Type is copy so ok to unwrap here
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

    let mut writer = WriterBuilder::new()
        .terminator(Terminator::CRLF)
        .from_path(&output_path)?;
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
    setting_value: Option<u32>,
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

fn get_current_applied_audit_policies() -> anyhow::Result<Vec<AuditCsvLine>> {
    let retrieve_all_sub_categories = BOOLEAN(0);
    let computer_name = std::env::var("ComputerName");
    let extracted_machine_name = computer_name.unwrap_or_else(|_| EMPTY_STRING.to_string());
    let mut pdw_count_returned: u32 = 0;
    let mut pp_audit_categories_array: *mut GUID = null_mut();

    let mut applied_audit_policies_sub_categories = vec![];
    let mut applied_audit_policies_sub_categories_content = EMPTY_STRING.to_string();

    unsafe {
        if AuditEnumerateCategories(
            &mut pp_audit_categories_array as *mut *mut GUID,
            &mut pdw_count_returned as *mut u32,
        )
        .0 == 0
        {
            let status = GetLastError();
            error!("Audit policies categories enumeration failed ({status:?})");
            return Err(anyhow::anyhow!(
                "Audit policies categories enumeration failed"
            ));
        }

        let sliced_categories_guids =
            from_raw_parts(pp_audit_categories_array, pdw_count_returned as usize);

        for p_audit_category_guid in sliced_categories_guids {
            let cat_uuid = Uuid::from_fields(
                p_audit_category_guid.data1,
                p_audit_category_guid.data2,
                p_audit_category_guid.data3,
                &p_audit_category_guid.data4,
            );

            let mut pp_audit_sub_categories_array: *mut GUID = null_mut();
            if AuditEnumerateSubCategories(
                p_audit_category_guid as *const GUID,
                retrieve_all_sub_categories,
                &mut pp_audit_sub_categories_array as *mut *mut GUID,
                &mut pdw_count_returned as *mut u32,
            )
            .0 == 0
            {
                let status = GetLastError();
                error!(
                    "Audit policies subcategories enumeration failed for category {cat_uuid} ({status:?})"
                );
                continue;
            }

            let sliced_sub_categories_guids =
                from_raw_parts(pp_audit_sub_categories_array, pdw_count_returned as usize);

            let mut pp_audit_sub_categories_information_array: *mut AUDIT_POLICY_INFORMATION =
                null_mut();
            if AuditQuerySystemPolicy(
                sliced_sub_categories_guids,
                &mut pp_audit_sub_categories_information_array
                    as *mut *mut AUDIT_POLICY_INFORMATION,
            )
            .0 == 0
            {
                let status = GetLastError();
                error!(
                    "Audit policies subcategories system policies query failed for category {cat_uuid} ({status:?})"
                );
                AuditFree(pp_audit_sub_categories_array as *const c_void);
                continue;
            }

            let sliced_sub_categories_informations = from_raw_parts(
                pp_audit_sub_categories_information_array,
                sliced_sub_categories_guids.len(),
            );

            for audit_sub_category_information in sliced_sub_categories_informations {
                let sub_cat_guid = audit_sub_category_information.AuditSubCategoryGuid;
                let sub_cat_uuid = Uuid::from_fields(
                    sub_cat_guid.data1,
                    sub_cat_guid.data2,
                    sub_cat_guid.data3,
                    &sub_cat_guid.data4,
                );

                let existing_audit_policy = AuditCsvLine {
                    machine_name: extracted_machine_name.clone(),
                    policy_target: "System".to_string(),
                    subcategory: EMPTY_STRING.to_string(),
                    subcategory_guid: format!("{{{}}}", sub_cat_uuid.to_string()),
                    inclusion_setting: EMPTY_STRING.to_string(),
                    exclusion_setting: EMPTY_STRING.to_string(),
                    setting_value: Some(audit_sub_category_information.AuditingInformation),
                };

                applied_audit_policies_sub_categories.push(existing_audit_policy.clone());
                applied_audit_policies_sub_categories_content = format!(
                    "{}{}",
                    applied_audit_policies_sub_categories_content,
                    format!(
                        "{},{},{},{},{},{},{:?}\r\n",
                        existing_audit_policy.machine_name,
                        existing_audit_policy.policy_target,
                        existing_audit_policy.subcategory,
                        existing_audit_policy.subcategory_guid,
                        existing_audit_policy.inclusion_setting,
                        existing_audit_policy.exclusion_setting,
                        existing_audit_policy.setting_value.unwrap_or(10),
                    )
                );
            }

            AuditFree(pp_audit_sub_categories_information_array as *const c_void);
            AuditFree(pp_audit_sub_categories_array as *const c_void);
        }

        AuditFree(pp_audit_categories_array as *const c_void);
    };

    info!(
        "Current applied subcategories audit policies content\r\n{}",
        applied_audit_policies_sub_categories_content
    );

    return Ok(applied_audit_policies_sub_categories);
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
    match get_gpresult_xml_for_user(temporary_task_folder, None) {
        Ok(xml) => return Ok(xml),
        Err(err) => warn!("RSoP file was not generated for current user: {err}"),
    };

    match get_gpresult_xml_for_user(temporary_task_folder, Some(administrator_name)) {
        Ok(xml) => return Ok(xml),
        Err(err) => warn!("RSoP file was not generated for {administrator_name}: {err}"),
    };

    let rsop_admins = get_powershell_unicode_output(
        "
        $domainSid = \"$((Get-ADDomain).DomainSID)\";
        Invoke-WmiMethod \
            -Class RsopLoggingModeProvider \
            -Name RsopEnumerateUsers \
            -Namespace Root\\RSOP \
        | Select \
            -ExpandProperty userSids \
        | Where-Object { $_.StartsWith($domainSid) } \
        | Get-ADUser -ErrorAction SilentlyContinue \
        | % { $_.SamAccountName }",
    );

    let rsop_admins = match rsop_admins {
        Ok(output) => {
            info!(
                "RSoP admins successfully computed from Invoke-WmiMethod RsopLoggingModeProvider"
            );
            output
        }
        Err(err) => {
            error!("RSoP admins cannot be generated from Invoke-WmiMethod RsopLoggingModeProvider: {err}");
            return Err(anyhow::anyhow!(err));
        }
    };

    let rsop_admins = rsop_admins
        .lines()
        .map(|n| n.trim())
        .filter(|n| !n.is_empty() && *n != administrator_name);

    for rsop_admin in rsop_admins {
        match get_gpresult_xml_for_user(temporary_task_folder, Some(rsop_admin)) {
            Ok(xml) => return Ok(xml),
            Err(err) => warn!("RSoP file was not generated for {rsop_admin}: {err}"),
        };
    }

    Err(anyhow::anyhow!(
        "RSoP file generation failed after several attempts"
    ))
}

fn get_gpresult_xml_for_user(
    temporary_task_folder: &TempDir,
    user_name: Option<&str>,
) -> anyhow::Result<Element> {
    let rsop_file_path = temporary_task_folder.path().join("rsop.xml");
    let rsop_file_path_name = rsop_file_path.to_string_lossy();

    if rsop_file_path.exists() {
        info!("Removing file at {rsop_file_path_name}");
        std::fs::remove_file(&rsop_file_path)?;
    }

    info!("Generating RSoP file at {rsop_file_path_name}");

    match user_name {
        None => {
            info!("Generating RSoP file at {rsop_file_path_name} for current user");
            run_command(format!(
                "gpresult.exe /SCOPE COMPUTER /X {rsop_file_path_name}"
            ))?;
        }
        Some(user_name) => {
            info!("Generating RSoP file at {rsop_file_path_name} for {user_name}");
            run_command(format!(
                "gpresult.exe /SCOPE COMPUTER /X {rsop_file_path_name} /USER {user_name}"
            ))?;
        }
    }

    if !rsop_file_path.exists() {
        return Err(anyhow::anyhow!("RSoP file generation failed"));
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

#[cfg(test)]
pub fn init_test_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
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
        use crate::configuration::{Arguments, EventsLogsConfiguration};
        use crate::setup::init_test_logger;
        use crate::sharing::file_sharing_manager::FileSharingManager;
        use crate::EMPTY_STRING;
        use crate::{
            setup::{handle_file_changes, FileChanged},
            EventLog,
        };
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use windows::Win32::System::EventLog::EVT_SUBSCRIBE_CALLBACK;

        #[test]
        fn with_empty_subscribed_channel_handles_should_feed_with_default_and_requested_channels() {
            init_test_logger();
            // Create a temporary file for test config.
            let tmp_file = EventsLogsConfiguration::create_default_configuration_file();
            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();
            let args = Arguments::default();
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let current_build_number = Some(42);
            let mut current_configuration = EventsLogsConfiguration::default();

            // Act
            handle_file_changes(
                &Arc::new(Mutex::new(FileSharingManager::new(
                    true,
                    Arguments::default(),
                    &EventsLogsConfiguration::default(),
                ))),
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
        fn with_populated_subscribed_channel_handles_should_clear_then_feed_with_default_and_requested_channels(
        ) {
            init_test_logger();
            // Create a temporary file for test config.
            let tmp_file = EventsLogsConfiguration::create_default_configuration_file();
            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();
            subscribed_channels.insert("ChannelName0".to_string(), 42);
            subscribed_channels.insert("ChannelName1".to_string(), 21);
            let args = Arguments::default();
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let current_build_number = Some(42);
            let mut current_configuration = EventsLogsConfiguration::default();

            // Act
            handle_file_changes(
                &Arc::new(Mutex::new(FileSharingManager::new(
                    true,
                    Arguments::default(),
                    &current_configuration,
                ))),
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
            init_test_logger();
            // Create a temporary file for test config.
            let tmp_file = EventsLogsConfiguration::create_default_configuration_file();

            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();

            // Insert some channels' names to ensure that the HashMap remains untouched.
            subscribed_channels.insert("ChannelName0".to_string(), 42);
            subscribed_channels.insert("ChannelName1".to_string(), 21);

            let args = Arguments::default();
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
                smb_mode_activated: false,
                relay_account_username: EMPTY_STRING.to_string(),
            };

            // Act
            handle_file_changes(
                &Arc::new(Mutex::new(FileSharingManager::new(
                    false,
                    Arguments::default(),
                    &EventsLogsConfiguration::default(),
                ))),
                tmp_file.path(),
                &mut subscribed_channels,
                &args,
                callback,
                current_build_number,
                &mut current_configuration,
                FileChanged::ConfigurationChanged,
                true,
            );

            // Asserts
            // Assert that the HashMap has not been cleared nor fed.
            assert_eq!(subscribed_channels.len(), 2);
            assert!(subscribed_channels.contains_key("ChannelName0"));
            assert!(subscribed_channels.contains_key("ChannelName1"));
        }

        #[test]
        fn when_new_config_is_different_from_current_should_apply_it_and_store_new_config() {
            init_test_logger();
            // Create a temporary file for test config.
            let tmp_file = EventsLogsConfiguration::create_default_configuration_file();
            let mut subscribed_channels: HashMap<String, isize> = HashMap::new();

            let args = Arguments::default();
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let current_build_number = Some(42);
            let mut current_configuration = EventsLogsConfiguration::default();
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
                smb_mode_activated: false,
                relay_account_username: EMPTY_STRING.to_string(),
            };

            // Act
            handle_file_changes(
                &Arc::new(Mutex::new(FileSharingManager::new(
                    true,
                    Arguments::default(),
                    &EventsLogsConfiguration::default(),
                ))),
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
        use std::env::temp_dir;

        use crate::setup::{
            get_audit_csv_data, get_current_applied_audit_policies, read_as_utf8_string,
            run_command, AuditCsvLine,
        };

        #[test]
        fn it_should_parse_the_rsop_xml_file() {
            let rsop_xml = include_str!("../data/rsop.xml");
            let result = rsop_xml.parse::<minidom::Element>();
            assert!(result.is_ok());
        }

        #[test]
        fn it_should_generate_same_output_windows_apis_vs_auditpol() {
            let audit_csv_temp_file_path = temp_dir().as_path().join("audit.csv");
            let audit_csv_temp_file_path_name = audit_csv_temp_file_path.to_string_lossy();

            let _ = run_command(format!(
                "auditpol.exe /backup /file:\"{audit_csv_temp_file_path_name}\""
            ));

            let auditpol_string = read_as_utf8_string(audit_csv_temp_file_path);
            let auditpol_output: Vec<AuditCsvLine> = get_audit_csv_data(auditpol_string.unwrap())
                .unwrap()
                .into_iter()
                .filter(|v| v.subcategory_guid != "")
                .collect();

            let audit_policies_windows_apis = get_current_applied_audit_policies().unwrap();

            assert_eq!(audit_policies_windows_apis.len(), auditpol_output.len());

            let check_all_vec_values = audit_policies_windows_apis.iter().all(|f| {
                auditpol_output
                    .iter()
                    .any(|g| g.subcategory_guid == f.subcategory_guid)
            });

            assert!(check_all_vec_values);
        }
    }

    mod extract_gpo_guid_from_path {
        use super::super::*;
        #[test]
        fn it_should_extract_the_gpo_guid_from_pol_file_path() {
            let guid_st = "ad9f25ab-5c6e-4501-a129-1d1dfb3bae5e";
            let path = format!("\\\\Server2022.alsid.com\\sysvol\\alsid.com\\Policies\\{{{}}}\\Machine\\Registry.pol", guid_st);
            let result = extract_gpo_guid_from_path(&path);
            assert!(result.is_some());
            assert_eq!(guid_st, result.unwrap());
        }

        #[test]
        fn when_path_is_invalid_it_should_return_none() {
            let path = "Not\\A\\Valid\\Path";
            let result = extract_gpo_guid_from_path(&path);
            assert!(result.is_none());
        }
    }

    mod patch_gPCMachineExtensionNames {
        use super::super::*;

        const audit_applied_gPCMachineExtensionNames: &str = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";
        fn get_audit_not_applied_gPCMachineExtensionNames() -> String {
            audit_applied_gPCMachineExtensionNames.replace(AUDIT_KEY, "")
        }
        const auditCsvGenerationNoOk: bool = false;
        const auditCsvGenerationOk: bool = !auditCsvGenerationNoOk;

        #[test]
        fn when_audit_csv_geneation_failed_it_should_remove_audit_key_from() {
            // Act
            let patched = get_patched_gPCMachineExtensionNames(
                &audit_applied_gPCMachineExtensionNames.to_string(),
                auditCsvGenerationNoOk,
            );

            // Assert
            assert_eq!(get_audit_not_applied_gPCMachineExtensionNames(), patched);
        }

        #[test]
        fn when_audit_csv_geneation_failed_and_no_audit_key_then_keep_untouched() {
            // Arrange
            let noAudit = get_audit_not_applied_gPCMachineExtensionNames();

            // Act
            let patched = get_patched_gPCMachineExtensionNames(&noAudit, auditCsvGenerationNoOk);

            // Assert
            assert_eq!(noAudit, patched);
        }

        #[test]
        fn when_audit_csv_geneation_Ok_and_no_audit_key_then_add_audit_key() {
            // Arrange
            let noAudit = get_audit_not_applied_gPCMachineExtensionNames();

            // Act
            let patched = get_patched_gPCMachineExtensionNames(&noAudit, auditCsvGenerationOk);

            // Assert
            assert_eq!(audit_applied_gPCMachineExtensionNames, patched);
        }

        #[test]
        fn when_audit_csv_geneation_Ok_and_audit_key_present_then_keep_untouched() {
            // Act
            let patched = get_patched_gPCMachineExtensionNames(
                &audit_applied_gPCMachineExtensionNames.to_string(),
                auditCsvGenerationOk,
            );

            // Assert
            assert_eq!(audit_applied_gPCMachineExtensionNames, patched);
        }
    }

    mod sort_gPCMachineExtensionNames {
        use super::super::*;

        #[test]
        fn when_not_sorted_then_sort() {
            // Arrange
            let input = "[{23CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{B3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{43CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";

            // Act
            let sorted = sort_gPCMachineExtensionNames(input);

            // Assert
            let expected = "[{23CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{43CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{B3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";
            assert_eq!(expected, sorted);
        }

        #[test]
        fn when_not_sorted_then_sort_2() {
            // Arrange
            let input = "[{23CCC681-B74C-4060-9F26-CD84525DCA2B}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{23CCC681-B74C-4060-9F26-CD84525DCA2A}{1F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";

            // Act
            let sorted = sort_gPCMachineExtensionNames(input);

            // Assert
            let expected = "[{23CCC681-B74C-4060-9F26-CD84525DCA2A}{1F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{23CCC681-B74C-4060-9F26-CD84525DCA2B}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";
            assert_eq!(expected, sorted);
        }

        #[test]
        fn when_not_sorted_then_sort_3() {
            // Arrange
            let input = "[{23CCC681-B74C-4060-9F26-CD84525DCA2A}{1F3F3735-573D-9804-99E4-AB2A69BA5FD4}][{23CCC681-B74C-4060-9F26-CD84525DCA2B}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";

            // Act
            let sorted = sort_gPCMachineExtensionNames(input);

            // Assert
            assert_eq!(input, sorted);
        }
    }
}
