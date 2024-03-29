#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use chrono::{DateTime, Duration, Local, Utc};
use clap::Parser;
use core::ffi::c_void;
use env_logger::{Builder, Target};
use flate2::{write::GzEncoder, Compression};
use gag::BufferRedirect;
use gethostname::gethostname;
use log::{error, info, warn, LevelFilter};
use memory_stats::memory_stats;
use minidom::Element;
use notify::{Error, Event, ReadDirectoryChangesWatcher, Result as NotifyResult, Watcher};
use serde::Deserialize;
use state::Storage;
use std::{
    collections::{HashMap, HashSet},
    env::{current_dir, temp_dir, VarError},
    ffi::OsString,
    fs::{self, create_dir},
    io::{Read, Write},
    num::NonZeroU8,
    os::windows::prelude::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        mpsc::{channel, Receiver, Sender, TryRecvError},
        Mutex,
    },
    time::{Duration as StdTimeDuration, Instant},
    {ptr::null_mut, thread},
};
use timer::Timer;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
};
use windows::Win32::Security;
use windows::Win32::Storage::FileSystem;
use windows::Win32::System::EventLog::*;
use windows::Win32::System::JobObjects;
use windows::Win32::System::Threading;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

mod channel;
mod setup;

use setup::{
    generate_audit_csv, generate_gpt_tmpl_inf, generate_registry_pol, handle_file_changes,
    log_configuration, read_setup_from_file, run_command, subscribe_to_channels, FileChanged,
    SYNC_FILE_PATH,
};

const EVT_RENDER_FLAG_EVENT_XML: u32 = windows::Win32::System::EventLog::EvtRenderEventXml.0 as u32;
const NAME: &str = "Name";
const SYSTEM_TIME: &str = "SystemTime";
const DATE_TIME_FORMAT: &str = "%Y%m%d%H%M%S%.6f-000";
const QUOTE: &str = "\"";
const EMPTY_STRING: &str = "";
const ZERO_STRING: &str = "0";
const TIME_CREATED: &str = "TimeCreated";
const EVENT_LOGS_COUNT_LEAP: u32 = 1000; // Event logs counter leap to wait
const DEFAULT_CONFIGURATION_FILE_PATH: &str = "./TenableADEventsListenerConfiguration.json";

const ONE_MINUTE: StdTimeDuration = StdTimeDuration::from_secs(60);

// Define insertion string list delimiter
// We currently use the following sequence: \u001F\u001E
// which contains the Unit Separator and the Record Separator character
// and should never appears in an insertion string.
const DATA_DELIMITER: &str = "\u{1f}\u{1e}";

static mut MAX_MEMORY_SIZE_BYTES: usize = 524288000; // Maximum listener memory size
static mut MAX_THROUGHPUT: f32 = 1500.0; // Maximum throughput, in events per second
static mut DURATION_LEAP: StdTimeDuration = StdTimeDuration::from_millis(10); // Duration leap to adjust throttling
static mut SLEEP_DURATION: StdTimeDuration = StdTimeDuration::ZERO; // Duration to throttle event logs handler
static mut PREVIEW: bool = false; // Enable or disable preview features
static mut EVENT_LOGS_COUNT: u32 = 0; // Event logs counter
static BUFFER: Storage<Mutex<Vec<u8>>> = Storage::new(); // Buffer to store event logs momentarily
static LOG_BUFFER: Storage<Mutex<BufferRedirect>> = Storage::new(); // Buffer to store logs momentarily

#[derive(Deserialize, PartialEq, Eq, Hash)]
pub struct EventLog {
    #[serde(alias = "Id", alias = "id")]
    id: u32,

    #[serde(alias = "ProviderName", alias = "providerName")]
    provider_name: String,
}

#[derive(Deserialize)]
pub struct EventsLogsConfiguration {
    #[serde(alias = "Events", alias = "events")]
    events: Vec<EventLog>,

    #[serde(alias = "Channels", alias = "channels")]
    channels: Vec<String>,

    #[serde(alias = "Audit", alias = "audit")]
    audit: Vec<String>,

    #[serde(alias = "RegistryValues", alias = "registryValues")]
    registry_values: Vec<String>,

    #[serde(alias = "PolRegistryValues", alias = "polRegistryValues")]
    pol_values: Vec<String>,
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
    }
}

#[derive(Parser, Debug)]
#[clap(
    about = "This command launches an event listener, which forwards each received event to an internal memory buffer. This buffer is flushed to the disk periodically."
)]
pub struct Arguments {
    #[clap(
        short = 'p',
        long = "EventLogFilePath",
        help = "The file where events are written"
    )]
    event_log_file_path: String,

    #[clap(
        short = 't',
        long = "TimerDurationSeconds",
        help = "The interval between each file write"
    )]
    timer_duration_seconds: u32,

    #[clap(
        short = 'b',
        long = "MaxBufferSizeBytes",
        default_value = "524288000",
        help = "The maximum buffer size in bytes"
    )]
    max_buffer_size_bytes: usize,

    #[clap(
        short = 's',
        long = "MaxThroughput",
        default_value = "1500",
        help = "The maximum handled throughput, in event logs per second"
    )]
    max_throughput: u32,

    #[clap(
        short = 'd',
        long = "DurationLeapMilliSeconds",
        default_value = "10",
        help = "The duration leap to adjust events logs consumption throughput, in milliseconds"
    )]
    duration_leap: u64,

    #[clap(
        short = 'g',
        long = "EnableGzip",
        action,
        help = "Whether GZip compression is enabled"
    )]
    enable_gzip: bool,

    #[clap(
        short = 'r',
        long = "CpuRate",
        default_value = "20",
        help = "Control the CPU rate of the process (does not work on Windows Sever 2008R2 and below)"
    )]
    cpu_rate: NonZeroU8,

    #[clap(
        short = 'w',
        long = "Preview",
        action,
        help = "Enable preview features"
    )]
    preview: bool,

    #[clap(
        short = 'f',
        long = "AuditFolder",
        help = "Path of the folder containing the audit.csv file in the GPO"
    )]
    audit_folder: String,

    #[clap(
        short = 'a',
        long = "AdministratorName",
        help = "Name of the administrator account that can be used to execute some operations"
    )]
    administrator_name: String,

    #[clap(short = 'i', long = "PdcName", help = "Name of the PDC")]
    pdc_name: String,

    #[clap(short = 'y', long = "DomainName", help = "Name of the domain")]
    domain_name: String,

    #[clap(
        short = 'z',
        long = "DomainControllerDnsName",
        help = "DNS name of the domain controller"
    )]
    domain_controller_dns_name: String,

    #[clap(
        short = 'x',
        long = "GptTmplFile",
        help = "Path of the GptTmpl.inf file in the GPO"
    )]
    gpt_tmpl_file: String,

    #[clap(
        short = 'l',
        long = "RegistryPolFile",
        help = "Path of the Registry.pol file in the GPO"
    )]
    registry_pol_file: String,

    #[clap(
        long = "ConfigurationUpdateIntervalInMinutes",
        default_value = "5",
        help = "Minimum interval between each configuration update"
    )]
    conf_interval_in_minutes: NonZeroU8,
}

fn main() {
    let log_file_path = setup_log();
    info!("*****************************************************************************");
    info!("Starting event logs listener...");

    let args = match Arguments::try_parse() {
        Ok(args) => args,
        Err(err) => {
            error!("An error occurred while trying to parse the arguments: {err}");
            err.exit();
        }
    };

    let enable_gzip = args.enable_gzip;
    let event_log_file_path = args.event_log_file_path.clone();
    let timer_duration_seconds = args.timer_duration_seconds;
    let duration_as_float = timer_duration_seconds as f32;
    let duration_as_integer = args.timer_duration_seconds as i64;
    let cpu_rate = args.cpu_rate;
    let audit_folder = args.audit_folder.clone();
    let administrator_name = args.administrator_name.clone();
    let conf_interval = ONE_MINUTE * args.conf_interval_in_minutes.get() as u32;

    let is_pdc = match is_pdc(args.pdc_name.as_str()) {
        Ok(v) => v,
        Err(err) => {
            error!(
                "An error occurred while trying to check if the current computer is the PDC, \
                it will be considered as a normal DC: {err}"
            );
            false
        }
    };

    unsafe {
        PREVIEW = args.preview;
        MAX_MEMORY_SIZE_BYTES = args.max_buffer_size_bytes;
        MAX_THROUGHPUT = args.max_throughput as f32;
        DURATION_LEAP = StdTimeDuration::from_millis(args.duration_leap);
    }

    // Configuration
    let path = Path::new(DEFAULT_CONFIGURATION_FILE_PATH);
    wait_for_setup_file(path);

    let (mut configuration_file_json, configuration_file_content) = match read_setup_from_file(path)
    {
        Ok(result) => result,
        Err(err) => {
            // TODO: Add a retry mechanism?
            error!("An error occurred while reading the setup file: {err}");
            std::process::exit(err.raw_os_error().unwrap_or(1));
        }
    };

    log_configuration(configuration_file_content, &args);

    set_processor_limit(cpu_rate);

    // Flush
    let timer = Timer::new();
    let log_file_path_clone = log_file_path.clone();
    let _timer_guard =
        timer.schedule_repeating(Duration::seconds(duration_as_integer), move || {
            let mut buffer_content = match BUFFER.get().lock() {
                Ok(b) => b,
                Err(err) => {
                    error!("Error occurred during buffer retrieval: {err:?}");
                    return;
                }
            };

            try_adjust_throughput(&duration_as_float);

            flush_events_to_file(&enable_gzip, &event_log_file_path, &buffer_content);

            buffer_content.clear();
            buffer_content.shrink_to_fit();

            try_flush_log_buffer(log_file_path_clone.clone());
        });

    // Buffer
    let mut buffer_vec = Vec::new();

    // Custom start event
    add_start_event(&mut buffer_vec, Utc::now());
    BUFFER.set(Mutex::new(buffer_vec));

    // Generate audit.csv
    if let Err(err) = generate_audit_csv(
        &configuration_file_json.audit,
        audit_folder.clone().into(),
        &administrator_name[..],
        is_pdc,
    ) {
        error!("An error ocurred while trying to generate the audit.csv file: {err}");
    }

    // Generate GptTmpl.inf
    if let Err(err) = generate_gpt_tmpl_inf(
        &configuration_file_json.registry_values,
        args.gpt_tmpl_file.clone().into(),
        is_pdc,
    ) {
        error!("An error occurred while trying to generate the GptTmpl.inf file: {err}");
    }

    // Generate Registry.pol
    if let Err(err) = generate_registry_pol(
        &configuration_file_json.pol_values,
        &args.registry_pol_file[..],
        &args.domain_name[..],
        &args.domain_controller_dns_name[..],
        is_pdc,
    ) {
        error!("An error occurred while trying to generate the Registry.pol file: {err}");
    }

    // Force gpupdate
    if let Err(err) = run_command("gpupdate /force") {
        error!("An error occurred while trying to force the GP update: {err}");
    }

    // Subscriptions
    let callback: EVT_SUBSCRIBE_CALLBACK = Some(subscription_callback);
    let mut subscribed_channels: HashMap<String, isize> = HashMap::new();
    let current_build_number = try_get_current_build_number();
    subscribe_to_channels(
        callback,
        current_build_number,
        &configuration_file_json,
        &mut subscribed_channels,
    );

    let (channel_sender, receiver): (Sender<()>, Receiver<()>) = channel();

    // We need to declare this variable here so the value it refers to never goes out of scope.
    // This is done to prevent the ReadDirectoryChangeWatcher object from being dropped which would cancel the monitoring.
    let _file_watchers = if is_pdc {
        let config_watcher_sender = channel_sender.clone();

        let config_watcher_result =
            notify::recommended_watcher(move |res: NotifyResult<Event>| match res {
                Ok(event) if event.kind.is_modify() => {
                    info!("Received notification about changes on the configuration file");
                    if let Err(e) = config_watcher_sender.send(()) {
                        error!(
                            "An error has occured while trying to send change notification: {e}"
                        );
                    }
                }
                Ok(_) => info!(
                    "configuration file has been touched but not modified, \
                    there is not changes to apply."
                ),
                Err(e) => {
                    error!("An error has occurred while watching configuration file changes: {e}")
                }
            });

        let config_watcher = setup_file_to_watch(path, config_watcher_result);
        vec![config_watcher]
    } else {
        vec![]
    };

    // Service loop
    info!("Listening to event logs...");
    try_flush_log_buffer(log_file_path);
    if is_pdc {
        let mut last_event = None;

        loop {
            match receiver.try_recv() {
                Ok(_) => match last_event {
                    None => {
                        info!(
                            "Configuration update has been requested, \
                            execution scheduled in {} minutes",
                            args.conf_interval_in_minutes
                        );
                        last_event = Some(Instant::now());
                    }
                    _ => {}
                },
                Err(TryRecvError::Disconnected) => {
                    error!("An error has occurred while trying to receive file changes notification, configuration will not be updated");
                    thread::sleep(ONE_MINUTE);
                }
                // No messages are available in the channel's buffer
                Err(TryRecvError::Empty) => {}
            };

            let should_fire = match last_event {
                Some(ts) => Instant::now() > ts + conf_interval,
                _ => false,
            };

            if should_fire {
                handle_file_changes(
                    path,
                    &mut subscribed_channels,
                    &args,
                    callback,
                    current_build_number,
                    &mut configuration_file_json,
                    FileChanged::ConfigurationChanged,
                    is_pdc,
                );
                last_event = None;
            }

            thread::sleep(StdTimeDuration::from_secs(1));
        }
    } else {
        // Loops every five minute to resubscribe if the version of the sync file has changed
        let mut version = None;

        loop {
            thread::sleep(conf_interval);

            let new_version = match std::fs::read(SYNC_FILE_PATH) {
                Ok(content) => Some(content),
                Err(_) => None,
            };

            if new_version != version {
                info!(
                    "The version of the synchronization file ({SYNC_FILE_PATH}) has changed: \
                    previous value was {version:?}, new value is {new_version:?}",
                );

                handle_file_changes(
                    path,
                    &mut subscribed_channels,
                    &args,
                    callback,
                    current_build_number,
                    &mut configuration_file_json,
                    FileChanged::SyncFileChanged,
                    is_pdc,
                );

                version = new_version;
            }
        }
    }
}

fn try_flush_log_buffer(log_file_path: PathBuf) {
    let mut log_buffer = match LOG_BUFFER.get().lock() {
        Ok(b) => b,
        Err(err) => {
            error!("Error occurred during log buffer retrieval: {err:?}");
            return;
        }
    };

    let mut output = String::new();
    let _buffer_size = log_buffer.read_to_string(&mut output);

    if output.is_empty() {
        return;
    }

    let log_file_open = fs::File::options()
        .create(true)
        .append(true)
        .read(true)
        .open(log_file_path.as_os_str());

    let mut log_file_open_result = match log_file_open {
        Ok(f) => f,
        Err(err) => {
            error!("Error occurred during log file retrieval: {err:?}");
            return;
        }
    };

    let _write_result = log_file_open_result.write_all(output.as_bytes());
}

fn setup_log() -> PathBuf {
    let log_level: LevelFilter = LevelFilter::Info;

    let _builder = Builder::new()
        .target(Target::Stdout)
        .filter_level(log_level)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {}",
                Local::now().to_rfc3339(),
                record.level(),
                record.args()
            )
        })
        .init();

    match BufferRedirect::stdout() {
        Ok(b) => LOG_BUFFER.set(Mutex::new(b)),
        Err(_err) => false,
    };

    let log_file_folder = match current_dir() {
        Ok(exe_folder_path) => exe_folder_path,
        Err(_e) => temp_dir(),
    }
    .join("transcripts");
    let _ = create_dir(&log_file_folder);

    let mut log_filename = OsString::new();
    log_filename.push("TenableLog_");
    log_filename.push(gethostname());
    log_filename.push(".log");
    log_file_folder.as_path().join(log_filename)
}

fn try_get_current_build_number() -> Option<u32> {
    let current_build = match get_current_build_number() {
        Err(err) => {
            error!("An error occurred while trying to verify current Windows version: {err:?}");
            return None;
        }
        Ok(n) => n,
    };

    info!("Current build number: {current_build}");

    Some(current_build)
}

fn get_current_build_number() -> Result<u32, Box<dyn std::error::Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let current_version = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")?;
    let current_build: String = current_version.get_value("CurrentBuild")?;
    let current_build: u32 = current_build.parse()?;

    Ok(current_build)
}

fn set_processor_limit(cpu_rate: NonZeroU8) {
    unsafe {
        let process = Threading::GetCurrentProcess();

        set_affinity(process);
        set_cpu_rate_control(process, cpu_rate);

        CloseHandle(process);
    }
}

unsafe fn set_affinity(process: HANDLE) {
    // Only use the first processor
    const FIRST_PROCESSOR_ID: usize = 0x1;

    let result = Threading::SetProcessAffinityMask(process, FIRST_PROCESSOR_ID);

    if let Err(err) = result.ok() {
        error!("The affinity of the process was not set to '{FIRST_PROCESSOR_ID:#X}': {err:?}");
        return;
    }

    info!("The affinity of the process was set to {FIRST_PROCESSOR_ID:#X}");
}

unsafe fn set_cpu_rate_control(process: HANDLE, cpu_rate: NonZeroU8) {
    const JOB_OBJECT_NAME: &str = "Tenable.AD Job";

    let job_object_attributes = Security::SECURITY_ATTRIBUTES::default();

    let job_object = JobObjects::CreateJobObjectW(&job_object_attributes, JOB_OBJECT_NAME);

    let job_object = match job_object {
        Ok(v) => v,
        Err(err) => {
            error!(
                "The CPU rate control was not set because \
                the job object '{JOB_OBJECT_NAME}' could not be created: {err:?}"
            );
            return;
        }
    };

    let result = set_cpu_rate_control_on_job(job_object, process, cpu_rate);
    if !result {
        CloseHandle(job_object);
        return;
    }

    info!(
        "The job object '{JOB_OBJECT_NAME}' was assigned to the process \
        to control the CPU rate to {cpu_rate}%"
    );
    CloseHandle(job_object);
}

unsafe fn set_cpu_rate_control_on_job(
    job_object: HANDLE,
    process: HANDLE,
    cpu_rate: NonZeroU8,
) -> bool {
    const ENABLE_HARD_CAP: u32 = JobObjects::JOB_OBJECT_CPU_RATE_CONTROL_ENABLE.0
        + JobObjects::JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP.0;

    let info_class = JobObjects::JobObjectCpuRateControlInformation;
    let info_cpu_rate = JobObjects::JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        ControlFlags: JobObjects::JOB_OBJECT_CPU_RATE_CONTROL(ENABLE_HARD_CAP),
        Anonymous: JobObjects::JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
            CpuRate: cpu_rate.get() as u32 * 100,
        },
    };

    let info_ptr = std::ptr::addr_of!(info_cpu_rate);
    let info_size = std::mem::size_of_val(&info_cpu_rate) as u32;

    // WARNING: This is not supported on Windows Server 2008R2 and below:
    // it will return an error 87 (ERROR_INVALID_PARAMETERS) and fail silently
    let result =
        JobObjects::SetInformationJobObject(job_object, info_class, info_ptr as _, info_size);

    if let Err(err) = result.ok() {
        error!("The CPU rate control could not be set on the job object: {err:?}");
        return false;
    }

    // WARNING: The handle must have sufficient privileges to call this function.
    // Also, on Windows Server 2008R2 and below the process must not already be assigned to a job.
    let result = JobObjects::AssignProcessToJobObject(job_object, process);

    if let Err(err) = result.ok() {
        error!("The job object could not be assigned to the process: {err:?}");
        return false;
    }

    return true;
}

unsafe extern "system" fn subscription_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    _usercontext: *const c_void,
    h_event: isize,
) -> u32 {
    match action {
        EvtSubscribeActionDeliver => {
            match memory_stats() {
                Some(m) => {
                    // Discard events if the memory limit is reached
                    if (m.physical_mem >= MAX_MEMORY_SIZE_BYTES)
                        || (m.virtual_mem >= MAX_MEMORY_SIZE_BYTES)
                    {
                        return 1;
                    }
                }
                None => {}
            }

            let formatted_event = render_event(h_event, EVT_RENDER_FLAG_EVENT_XML);

            if formatted_event == EMPTY_STRING {
                return 1;
            }

            match BUFFER.get().lock() {
                Ok(mut acquired_vec_state) => {
                    let event_bytes = formatted_event.as_bytes();

                    acquired_vec_state.extend(event_bytes);

                    if !SLEEP_DURATION.is_zero() {
                        wait();
                    }
                    EVENT_LOGS_COUNT = EVENT_LOGS_COUNT + 1;
                    0
                }
                Err(_e) => 1,
            }
        }
        EvtSubscribeActionError => 1,
        _ => 1,
    }
}

fn flush_events_to_file(enable_gzip: &bool, file_path: &String, file_content: &Vec<u8>) {
    if file_content.is_empty() {
        return;
    }

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
        Err(_e) => return,
    };

    if *enable_gzip {
        let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());

        let _compress_result = match gz_encoder.write_all(&file_content) {
            Ok(c) => c,
            Err(_e) => return,
        };

        let final_gz_stream = match gz_encoder.finish() {
            Ok(c) => c,
            Err(_e) => return,
        };
        let _write_gz_result = events_file.write_all(&final_gz_stream);

        return;
    }

    let _write_result = events_file.write_all(&file_content);
}

fn try_adjust_throughput(duration_as_float: &f32) {
    unsafe {
        let current_throughput = EVENT_LOGS_COUNT as f32 / duration_as_float;

        if current_throughput > MAX_THROUGHPUT {
            SLEEP_DURATION = match SLEEP_DURATION.checked_add(DURATION_LEAP) {
                Some(d) => d,
                None => SLEEP_DURATION,
            };
            try_log_sleep_adjust(current_throughput);
        } else if !SLEEP_DURATION.is_zero() && current_throughput < MAX_THROUGHPUT {
            SLEEP_DURATION = match SLEEP_DURATION.checked_sub(DURATION_LEAP) {
                Some(d) => d,
                None => SLEEP_DURATION,
            };
            try_log_sleep_adjust(current_throughput);
        }

        EVENT_LOGS_COUNT = 0;
    }
}

fn try_log_sleep_adjust(current_throughput: f32) {
    unsafe {
        if current_throughput < (MAX_THROUGHPUT + 500.0) {
            return;
        }

        let sleep_duration_millis = SLEEP_DURATION.as_millis();
        info!(
            "Dynamic sleep adjusted to {sleep_duration_millis} milliseconds, current throughput: {current_throughput} evts/sec."
        );
    }
}

fn wait() {
    unsafe {
        if EVENT_LOGS_COUNT == 0 || EVENT_LOGS_COUNT.rem_euclid(EVENT_LOGS_COUNT_LEAP) != 0 {
            return;
        }

        thread::sleep(SLEEP_DURATION);
    }
}

fn build_xml_query(events: &Vec<EventLog>, channel: &String) -> String {
    let query_node = Element::bare("Query", "");
    let mut query_list_node = Element::builder("QueryList", "").build();

    let appended_query_node = query_list_node.append_child(query_node);

    for event_log_kind in events {
        let filter = format!(
            "(EventID={}) and (Provider[@Name = '{}'])",
            event_log_kind.id, event_log_kind.provider_name
        );
        let event_provider_filter = format!("*[System[{}]]", filter);

        let event_element = Element::builder("Select", "")
            .attr("Path", channel)
            .append(event_provider_filter)
            .build();

        appended_query_node.append_child(event_element);
    }

    String::from(&query_list_node)
}

fn add_start_event(buffer: &mut Vec<u8>, now: DateTime<Utc>) {
    let mut start_event_data = String::new();
    for _n in 1..7 {
        start_event_data = format!(
            "{}{}",
            start_event_data,
            format!("{}{}{}{}", QUOTE, ZERO_STRING, QUOTE, DATA_DELIMITER)
        );
    }
    start_event_data = format!(
        "{}{}",
        start_event_data,
        format!("{}{}{}", QUOTE, ZERO_STRING, QUOTE)
    );

    let start_event_date = (now + Duration::hours(-1)).format(DATE_TIME_FORMAT);

    let start_event = format!(
        "({})#{}#{}#{}##{}##################\n",
        start_event_data, 12, 1, "Microsoft-Windows-Kernel-General", start_event_date
    );

    let start_event_bytes = start_event.as_bytes();

    buffer.extend(start_event_bytes);
}

fn render_event(h_event: isize, flag: u32) -> String {
    let mut buffersize = 0;
    let mut bufferused: u32 = 0;
    let mut properties_count: u32 = 0;

    unsafe {
        let _buffer_search = EvtRender(
            0,
            h_event,
            flag,
            buffersize,
            null_mut(),
            &mut bufferused as *mut u32,
            null_mut(),
        )
        .as_bool();

        let status = GetLastError();
        if status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER {
            return EMPTY_STRING.to_string();
        }

        buffersize = bufferused;
        let mut rendered_values: Vec<u16> = vec![0; buffersize as usize];

        let render_result = EvtRender(
            0,
            h_event,
            flag,
            buffersize,
            rendered_values.as_mut_ptr() as *mut c_void,
            &mut bufferused,
            &mut properties_count,
        )
        .as_bool();

        if !render_result {
            return EMPTY_STRING.to_string();
        }

        build_event_log_record(rendered_values)
    }
}

fn build_event_log_record(rendered_values: Vec<u16>) -> String {
    let read_xml = String::from_utf16_lossy(&rendered_values[..])
        .trim_matches(char::from(0))
        .to_string();

    let root: Element = match read_xml.parse() {
        Ok(c) => c,
        Err(_e) => return EMPTY_STRING.to_string(),
    };

    let mut root_children = root.children();

    // System
    let event_system_option = root_children.next();
    let event_system = match event_system_option {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let mut system_properties = event_system.children();
    let provider_name_option = match system_properties.next() {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let provider_name = match provider_name_option.attr(NAME) {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };

    let event_id = match system_properties.next() {
        Some(n) => n.text(),
        None => return EMPTY_STRING.to_string(),
    };

    let mut prop_count = 0;
    let created_date_time_raw_option = loop {
        prop_count += 1;
        if prop_count == 7 {
            return EMPTY_STRING.to_string();
        }

        break match system_properties.next() {
            Some(n) if n.name() == TIME_CREATED => n,
            _ => continue,
        };
    };

    let created_date_time_raw = match created_date_time_raw_option.attr(SYSTEM_TIME) {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let created_date_time_option = match created_date_time_raw.parse::<DateTime<Utc>>() {
        Ok(c) => c,
        Err(_e) => return EMPTY_STRING.to_string(),
    };
    let created_date_time = created_date_time_option.format(DATE_TIME_FORMAT);

    // Data
    let event_data = match root_children.next() {
        Some(n) => n,
        None => return EMPTY_STRING.to_string(),
    };
    let event_data_properties = event_data.children();
    let mut event_data_strings = String::new();
    let mut last_property_has_no_data = false;
    let mut data_properties_count = 0;
    for data_prop in event_data_properties {
        let prop_text = data_prop.text();
        last_property_has_no_data = prop_text == EMPTY_STRING;

        event_data_strings = format!(
            "{}{}",
            event_data_strings,
            format!("{}{}{}{}", QUOTE, data_prop.text(), QUOTE, DATA_DELIMITER)
        );

        data_properties_count = data_properties_count + 1;
    }

    // Handle eventual event data sub node
    if (data_properties_count == 1) && last_property_has_no_data {
        event_data_strings.clear();

        let event_sub_data = match event_data.children().next() {
            Some(n) => n,
            None => return EMPTY_STRING.to_string(),
        };

        event_data_strings = build_sub_event_data(event_sub_data);
    }

    let event_data_strings = remove_last_chars(&event_data_strings, 2);

    format!(
        "({})#{}##{}##{}##################\n",
        event_data_strings, event_id, provider_name, created_date_time
    )
}

fn build_sub_event_data(event_sub_data: &Element) -> String {
    let mut event_data_strings = String::new();
    let event_sub_data_properties = event_sub_data.children();

    for data_prop in event_sub_data_properties {
        event_data_strings = format!(
            "{}{}",
            event_data_strings,
            format!("{}{}{}{}", QUOTE, data_prop.text(), QUOTE, DATA_DELIMITER)
        );
    }

    event_data_strings
}

fn remove_last_chars(s: &String, n: usize) -> &str {
    if n <= 0 {
        return s;
    }

    let len = s.len();
    if n > len {
        return EMPTY_STRING;
    }

    let (result, _) = s.split_at(len - n);
    result
}

fn wait_for_setup_file(path: &Path) {
    info!("Start waiting for configuration file to be available at path: '{DEFAULT_CONFIGURATION_FILE_PATH}'...");

    while !path.exists() {
        thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn setup_file_to_watch(
    path: &Path,
    result: Result<ReadDirectoryChangesWatcher, Error>,
) -> Option<ReadDirectoryChangesWatcher> {
    match result {
        Ok(mut watcher) => {
            if let Err(e) = watcher.watch(path, notify::RecursiveMode::NonRecursive) {
                warn!("An error has occurred while starting to watch changes on file with path '{}': {e} (No automatic update will be available based on changes made to this file)", path.display());
                // We still return the watcher here because we will use it to try again to set the file to watcher later.
                Some(watcher)
            } else {
                info!("Start monitoring file with path: '{}'", path.display());
                Some(watcher)
            }
        }
        Err(e) => {
            warn!("An error has occurred while setting up the file watcher for file with path '{}': {e} (No automatic update will be available)", path.display());
            None
        }
    }
}

fn is_pdc(pdc_name: &str) -> Result<bool, VarError> {
    let current_name = std::env::var("ComputerName")?;

    info!("The name of the current computer is '{current_name}'");

    let is_pdc = current_name.to_ascii_lowercase() == pdc_name.to_ascii_lowercase();
    Ok(is_pdc)
}

#[cfg(test)]
mod tests {
    mod flush_events_to_file {
        use super::super::*;
        use std::fs::File;
        use tempfile::TempDir;

        #[test]
        fn it_should_create_the_file_if_it_does_not_exist() {
            // Arrange
            let tmp_dir = TempDir::new().unwrap();
            let tmp_dir_path = tmp_dir.path().to_str().unwrap();
            let tmp_file_path = format!("{tmp_dir_path}/out");

            let enable_gzip = false;
            let content = "Test".as_bytes().to_vec();

            // Act
            flush_events_to_file(&enable_gzip, &tmp_file_path, &content);

            // Assert
            let result = std::fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("Test", result);
        }

        #[test]
        fn it_should_overwrite_the_file_content() {
            // Arrange
            let (_tmp_dir, tmp_file_path) = get_tmp_file_path("123");

            let enable_gzip = false;
            let content = "456".as_bytes().to_vec();

            let result = std::fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("123", result);

            // Act
            flush_events_to_file(&enable_gzip, &tmp_file_path, &content);

            // Assert
            let result = std::fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("456", result);
        }

        #[test]
        fn it_should_not_work_if_the_file_is_not_accessible() {
            // Arrange
            let (_tmp_dir, tmp_file_path) = get_tmp_file_path("123");

            let enable_gzip = false;
            let content = "456".as_bytes().to_vec();

            let result = std::fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("123", result);

            let sharing_mode = FileSystem::FILE_SHARE_NONE;
            let file = fs::File::options()
                .create(true)
                .read(true)
                .write(true)
                .share_mode(sharing_mode.0)
                .open(&tmp_file_path);

            // Act
            flush_events_to_file(&enable_gzip, &tmp_file_path, &content);

            // Assert
            drop(file);
            let result = std::fs::read_to_string(&tmp_file_path).unwrap();
            assert_eq!("123", result);
        }

        #[test]
        fn it_should_compress_the_file_content_correctly() {
            // Arrange
            let (_tmp_dir, tmp_file_path) = get_tmp_file_path("123");

            let enable_gzip = true;
            let content = "456".as_bytes().to_vec();

            const compressed_content: [u8; 23] = [
                31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 51, 49, 53, 3, 0, 113, 195, 168, 177, 3, 0, 0, 0,
            ];

            // Act
            flush_events_to_file(&enable_gzip, &tmp_file_path, &content);

            // Assert
            let result = std::fs::read(&tmp_file_path).unwrap();
            assert_eq!(compressed_content.to_vec(), result);
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

    mod build_channels {
        use crate::setup::build_channels;

        #[test]
        fn it_should_add_channels_to_the_default_channels() {
            // Arrange
            let additional_channels = vec![
                "test1".to_string(),
                "test2".to_string(),
                "test3".to_string(),
            ];

            // Act
            let result = build_channels(&additional_channels);

            // Assert
            assert_eq!(
                vec![
                    "Security".to_string(),
                    "Application".to_string(),
                    "System".to_string(),
                    "test1".to_string(),
                    "test2".to_string(),
                    "test3".to_string(),
                ],
                result
            );
        }

        #[test]
        fn it_should_return_the_default_channels_when_no_additional_channels_are_given() {
            // Arrange
            let additional_channels = vec![];

            // Act
            let result = build_channels(&additional_channels);

            // Assert
            assert_eq!(
                vec![
                    "Security".to_string(),
                    "Application".to_string(),
                    "System".to_string(),
                ],
                result
            );
        }

        #[test]
        fn it_should_not_add_empty_channels() {
            // Arrange
            let additional_channels = vec![
                "".to_string(),
                "test1".to_string(),
                "".to_string(),
                "test2".to_string(),
                "".to_string(),
            ];

            // Act
            let result = build_channels(&additional_channels);

            // Assert
            assert_eq!(
                vec![
                    "Security".to_string(),
                    "Application".to_string(),
                    "System".to_string(),
                    "test1".to_string(),
                    "test2".to_string(),
                ],
                result
            );
        }
    }

    mod build_xml_query {
        use super::super::*;

        #[test]
        fn it_should_build_an_xml_query_containing_one_event() {
            // Arrange
            let channel = "System".to_string();
            let events = vec![EventLog {
                id: 4624,
                provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
            }];

            // Act
            let xml_query = build_xml_query(&events, &channel);

            // Assert
            assert_eq!(
                xml_query,
                "<QueryList>\
                    <Query>\
                        <Select Path=\"System\">\
                            *[System[(EventID=4624) and \
                            (Provider[@Name = 'Microsoft-Windows-Security-Auditing'])]]\
                        </Select>\
                    </Query>\
                </QueryList>",
            );
        }

        #[test]
        fn it_should_build_an_xml_query_containing_several_events() {
            // Arrange
            let channel = "Security".to_string();
            let events = vec![
                EventLog {
                    id: 4624,
                    provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                },
                EventLog {
                    id: 4634,
                    provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
                },
                EventLog {
                    id: 325,
                    provider_name: "ESENT".to_string(),
                },
            ];

            // Act
            let xml_query = build_xml_query(&events, &channel);

            // Assert
            assert_eq!(
                xml_query,
                "<QueryList>\
                    <Query>\
                        <Select Path=\"Security\">\
                            *[System[(EventID=4624) and \
                            (Provider[@Name = 'Microsoft-Windows-Security-Auditing'])]]\
                        </Select>\
                        <Select Path=\"Security\">\
                            *[System[(EventID=4634) and \
                            (Provider[@Name = 'Microsoft-Windows-Security-Auditing'])]]\
                        </Select>\
                        <Select Path=\"Security\">\
                            *[System[(EventID=325) and (Provider[@Name = 'ESENT'])]]\
                        </Select>\
                    </Query>\
                </QueryList>",
            );
        }
    }

    mod add_start_event {
        use super::super::*;
        use chrono::NaiveDate;

        #[test]
        fn it_should_add_a_start_event_in_the_buffer() {
            // Arrange
            let mut buffer = vec![];

            let now = NaiveDate::from_ymd(2022, 08, 01).and_hms(15, 08, 58);
            let now = DateTime::<Utc>::from_utc(now, Utc);

            // Act
            add_start_event(&mut buffer, now);

            // Assert
            assert_eq!(
                String::from_utf8(buffer).unwrap(),
                "(\"0\"\u{1f}\u{1e}\
                \"0\"\u{1f}\u{1e}\
                \"0\"\u{1f}\u{1e}\
                \"0\"\u{1f}\u{1e}\
                \"0\"\u{1f}\u{1e}\
                \"0\"\u{1f}\u{1e}\
                \"0\")\
                #12#1#Microsoft-Windows-Kernel-General##\
                20220801140858.000000-000##################\n"
            );
        }
    }

    mod build_event_log_record {
        use super::super::*;
        use windows::core::HSTRING;

        #[test]
        fn it_should_convert_an_xml_event_to_an_event_log() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                  <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                            Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" />\
                  <EventID>4688</EventID>\
                  <Version>2</Version>\
                  <Level>0</Level>\
                  <Task>13312</Task>\
                  <Opcode>0</Opcode>\
                  <Keywords>0x8020000000000000</Keywords>\
                  <TimeCreated SystemTime=\"2022-08-01T14:03:19.253078100Z\" />\
                  <EventRecordID>3784135</EventRecordID>\
                  <Correlation />\
                  <Execution ProcessID=\"4\" ThreadID=\"3120\" />\
                  <Channel>Security</Channel>\
                  <Computer>DC-ROOT.ROOT.DOMAIN</Computer>\
                  <Security />\
                 </System>\
                 <EventData>\
                  <Data Name=\"SubjectUserSid\">S-1-5-18</Data>\
                  <Data Name=\"SubjectUserName\">DC-ROOT$</Data>\
                  <Data Name=\"SubjectDomainName\">ROOT</Data>\
                  <Data Name=\"SubjectLogonId\">0x3e7</Data>\
                  <Data Name=\"NewProcessId\">0x1638</Data>\
                  <Data Name=\"NewProcessName\"> \
                   C:\\Windows\\System32\\backgroundTaskHost.exe\
                  </Data>\
                  <Data Name=\"TokenElevationType\">%%1936</Data>\
                  <Data Name=\"ProcessId\">0x3a0</Data>\
                  <Data Name=\"CommandLine\"> \
                   \"C:\\Windows\\system32\\backgroundTaskHost.exe\" \
                   -ServerName:CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca</Data>\
                  <Data Name=\"TargetUserSid\">S-1-0-0</Data>\
                  <Data Name=\"TargetUserName\">administrator</Data>\
                  <Data Name=\"TargetDomainName\">ROOT</Data>\
                  <Data Name=\"TargetLogonId\">0x77260</Data>\
                  <Data Name=\"ParentProcessName\">C:\\Windows\\System32\\svchost.exe</Data>\
                  <Data Name=\"MandatoryLabel\">S-1-16-4096</Data>\
                 </EventData>\
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(
                result,
                "(\"S-1-5-18\"\u{1f}\u{1e}\
                \"DC-ROOT$\"\u{1f}\u{1e}\
                \"ROOT\"\u{1f}\u{1e}\
                \"0x3e7\"\u{1f}\u{1e}\
                \"0x1638\"\u{1f}\u{1e}\
                \" C:\\Windows\\System32\\backgroundTaskHost.exe\"\u{1f}\u{1e}\
                \"%%1936\"\u{1f}\u{1e}\
                \"0x3a0\"\u{1f}\u{1e}\
                \" \"C:\\Windows\\system32\\backgroundTaskHost.exe\" \
                -ServerName:CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca\"\u{1f}\u{1e}\
                \"S-1-0-0\"\u{1f}\u{1e}\
                \"administrator\"\u{1f}\u{1e}\
                \"ROOT\"\u{1f}\u{1e}\
                \"0x77260\"\u{1f}\u{1e}\
                \"C:\\Windows\\System32\\svchost.exe\"\u{1f}\u{1e}\
                \"S-1-16-4096\")\
                #4688##Microsoft-Windows-Security-Auditing#\
                #20220801140319.253078-000##################\n"
            );
        }

        #[test]
        fn it_should_convert_an_xml_event_with_a_different_system_node_to_en_event_log() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                    <System>\
                        <Provider Name=\"VSSAudit\" />\
                        <EventID Qualifiers=\"0\">8222</EventID>\
                        <Level>0</Level>\
                        <Task>3</Task>\
                        <Keywords>0x80a0000000000000</Keywords>\
                        <TimeCreated SystemTime=\"2022-08-04T13:28:22.517359200Z\" />\
                        <EventRecordID>3986554</EventRecordID>\
                        <Channel>Security</Channel>\
                        <Computer>DC-ROOT.ROOT.DOMAIN</Computer>\
                        <Security UserID=\"S-1-5-18\" />\
                    </System>\
                    <EventData>\
                        <Data>S-1-5-21-3770311822-3616871986-1308186358-11269</Data>\
                        <Data>ROOT\\AttackerAdmin</Data>\
                        <Data>0x0000000000001630</Data>\
                        <Data>C:\\Windows\\System32\\esentutl.exe</Data>\
                        <Data>{f9f78cf6-f380-4c9e-93d0-fe3a03bc03b7}</Data>\
                        <Data>{abc28faa-32a4-4b26-a0da-b18c9471f751}</Data>\
                        <Data>{b5946137-7b9f-4925-af80-51abd60b20d5}</Data>\
                        <Data>DC-ROOT.ROOT.DOMAIN</Data>\
                        <Data>\\\\?\\Volume{ca4a3263-dfab-48ee-a67f-d64e5ef1ee5c}\\</Data>\
                        <Data>\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy14</Data>\
                    </EventData>\
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(
                result,
                "(\"S-1-5-21-3770311822-3616871986-1308186358-11269\"\u{1f}\u{1e}\
                \"ROOT\\AttackerAdmin\"\u{1f}\u{1e}\
                \"0x0000000000001630\"\u{1f}\u{1e}\
                \"C:\\Windows\\System32\\esentutl.exe\"\u{1f}\u{1e}\
                \"{f9f78cf6-f380-4c9e-93d0-fe3a03bc03b7}\"\u{1f}\u{1e}\
                \"{abc28faa-32a4-4b26-a0da-b18c9471f751}\"\u{1f}\u{1e}\
                \"{b5946137-7b9f-4925-af80-51abd60b20d5}\"\u{1f}\u{1e}\
                \"DC-ROOT.ROOT.DOMAIN\"\u{1f}\u{1e}\
                \"\\\\?\\Volume{ca4a3263-dfab-48ee-a67f-d64e5ef1ee5c}\\\"\u{1f}\u{1e}\
                \"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy14\")\
                #8222##VSSAudit##20220804132822.517359-000##################\n"
            );
        }

        #[test]
        fn it_should_convert_an_efs_xml_event_to_an_event_log() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                  <System>\
                    <Provider Name=\"Microsoft-Windows-EFS\" \
                              Guid=\"{3663a992-84be-40ea-bba9-90c7ed544222}\" />\
                    <EventID>1</EventID>\
                    <Version>0</Version>\
                    <Level>2</Level>\
                    <Task>0</Task>\
                    <Opcode>0</Opcode>\
                    <Keywords>0x8000000000000000</Keywords>\
                    <TimeCreated SystemTime=\"2022-08-03T16:03:02.067389300Z\" />\
                    <EventRecordID>19867</EventRecordID>\
                    <Correlation />\
                    <Execution ProcessID=\"716\" ThreadID=\"4816\" />\
                    <Channel>Microsoft-Windows-EFS/Debug</Channel>\
                    <Computer>DC-ROOT.ROOT.DOMAIN</Computer>\
                    <Security UserID=\"S-1-5-18\" />\
                  </System>\
                  <UserData>\
                    <EfsLogString1Data xmlns=\"http://schemas.microsoft.com/schemas/event/\
                                               Microsoft.Windows/1.0.0.0\">\
                      <FileNumber>6</FileNumber>\
                      <LineNumber>4769</LineNumber>\
                      <Param>53</Param>\
                    </EfsLogString1Data>\
                  </UserData>\
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(
                result,
                "(\"6\"\u{1f}\u{1e}\"4769\"\u{1f}\u{1e}\"53\")\
                #1##Microsoft-Windows-EFS##20220803160302.067389-000##################\n"
            );
        }

        #[test]
        fn it_should_convert_an_xml_event_to_an_event_log_with_no_data_when_no_data() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                  <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                            Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
                  <EventID>4688</EventID> \
                  <Version>2</Version> \
                  <Level>0</Level> \
                  <Task>13312</Task> \
                  <Opcode>0</Opcode> \
                  <Keywords>0x8020000000000000</Keywords> \
                  <TimeCreated SystemTime=\"2022-08-01T14:03:19.253078100Z\" /> \
                  <EventRecordID>3784135</EventRecordID> \
                  <Correlation /> \
                  <Execution ProcessID=\"4\" ThreadID=\"3120\" /> \
                  <Channel>Security</Channel> \
                  <Computer>DC-ROOT.ROOT.DOMAIN</Computer> \
                  <Security /> \
                 </System>\
                 <EventData>\
                 </EventData> \
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(
                result,
                "()#4688##Microsoft-Windows-Security-Auditing#\
                #20220801140319.253078-000##################\n"
            );
        }

        #[test]
        fn it_should_return_an_empty_string_when_root_has_no_children() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }

        #[test]
        fn it_should_return_an_empty_string_when_system_has_no_children() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                 </System>\
                 <EventData>\
                 </EventData> \
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }

        #[test]
        fn it_should_return_an_empty_string_when_provider_has_no_name() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                  <Provider Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
                 </System>\
                 <EventData>\
                 </EventData> \
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }

        #[test]
        fn it_should_return_an_empty_string_when_there_is_no_event_id() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                  <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                            Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
                 </System>\
                 <EventData>\
                 </EventData> \
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }

        #[test]
        fn it_should_return_an_empry_string_when_there_is_no_time_created() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                  <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                            Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
                  <EventID>4688</EventID> \
                  <Version>2</Version> \
                  <Level>0</Level> \
                  <Task>13312</Task> \
                  <Opcode>0</Opcode> \
                  <Keywords>0x8020000000000000</Keywords> \
                 </System>\
                 <EventData>\
                 </EventData> \
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }

        #[test]
        fn it_should_return_an_empty_string_when_there_is_no_event_data() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                  <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                            Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
                  <EventID>4688</EventID> \
                  <Version>2</Version> \
                  <Level>0</Level> \
                  <Task>13312</Task> \
                  <Opcode>0</Opcode> \
                  <Keywords>0x8020000000000000</Keywords> \
                  <TimeCreated SystemTime=\"2022-08-01T14:03:19.253078100Z\" /> \
                  <EventRecordID>3784135</EventRecordID> \
                  <Correlation /> \
                  <Execution ProcessID=\"4\" ThreadID=\"3120\" /> \
                  <Channel>Security</Channel> \
                  <Computer>DC-ROOT.ROOT.DOMAIN</Computer> \
                  <Security /> \
                 </System>\
                </Event>",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }

        #[test]
        fn it_should_return_an_empty_string_when_given_an_invalid_xml() {
            // Arrange
            let event = HSTRING::from(
                "\
                <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                 <System>\
                  <Provider Name=\"Microsoft-Windows-Security-Auditing\" \
                            Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\" /> \
                ...",
            );

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }

        #[test]
        fn it_should_return_an_empty_string_when_given_an_empty_string() {
            // Arrange
            let event = HSTRING::from("");

            // Act
            let result = build_event_log_record(event.as_wide().to_vec());

            // Assert
            assert_eq!(result, "");
        }
    }

    mod try_adjust_throughput {
        use super::super::*;

        #[test]
        fn it_should_adjust_throughput_down() {
            // Arrange
            unsafe {
                EVENT_LOGS_COUNT = 45000;
                MAX_THROUGHPUT = 1500.0;
                SLEEP_DURATION = StdTimeDuration::ZERO;
                DURATION_LEAP = StdTimeDuration::from_millis(10);
                let n: f32 = 15.0;

                // Act
                try_adjust_throughput(&n);

                // Assert
                assert_eq!(SLEEP_DURATION, DURATION_LEAP);
            }
        }

        #[test]
        fn it_should_adjust_throughput_up() {
            // Arrange
            unsafe {
                EVENT_LOGS_COUNT = 12000;
                MAX_THROUGHPUT = 1500.0;
                SLEEP_DURATION = StdTimeDuration::from_millis(50);
                DURATION_LEAP = StdTimeDuration::from_millis(10);
                let n: f32 = 15.0;

                // Act
                try_adjust_throughput(&n);

                // Assert
                assert_eq!(SLEEP_DURATION, StdTimeDuration::from_millis(40));
            }
        }
    }

    mod remove_last_chars {
        use super::super::*;

        #[test]
        fn it_should_not_remove_0_chars() {
            // Arrange
            let s = String::from("Hello, world!");
            let n = 0;

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "Hello, world!");
        }

        #[test]
        fn it_should_remove_the_last_char() {
            // Arrange
            let s = String::from("Hello, world!");
            let n = 1;

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "Hello, world");
        }

        #[test]
        fn it_should_remove_the_last_2_chars() {
            // Arrange
            let s = String::from("Hello, world!");
            let n = 2;

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "Hello, worl");
        }

        #[test]
        fn it_should_remove_all_chars() {
            // Arrange
            let s = String::from("Hello, world!");
            let n = s.len();

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "");
        }

        #[test]
        fn it_should_remove_all_chars_on_overflow() {
            // Arrange
            let s = String::from("Hello, world!");
            let n = s.len() + 1;

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "");
        }

        #[test]
        fn it_should_remove_all_chars_when_the_string_has_the_same_size() {
            // Arrange
            let s = String::from("HW");
            let n = s.len() + 1;

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "");
        }

        #[test]
        fn it_should_remove_all_chars_when_the_string_is_too_small() {
            // Arrange
            let s = String::from("H");
            let n = s.len() + 1;

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "");
        }

        #[test]
        fn it_should_remove_all_chars_when_the_string_is_empty() {
            // Arrange
            let s = String::from("");
            let n = s.len() + 1;

            // Act
            let s = remove_last_chars(&s, n);

            // Assert
            assert_eq!(s, "");
        }
    }

    mod subscribe_to_channel {
        use super::super::*;
        use crate::setup::subscribe_to_channel;
        use windows::Win32::Foundation::{ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_QUERY};

        #[test]
        fn it_should_subscribe_to_a_valid_channel_and_event() {
            // Arrange
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let channel = "Security".to_string();
            let event_logs = vec![EventLog {
                id: 4658,
                provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
            }];

            // Act
            let result = subscribe_to_channel(&event_logs, &channel, callback, None);

            // Assert
            assert!(result.is_ok());
        }

        #[test]
        fn it_should_not_subscribe_to_an_invalid_channel() {
            // Arrange
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let channel = "Invalid".to_string();
            let event_logs = vec![EventLog {
                id: 4658,
                provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
            }];

            // Act
            let result = subscribe_to_channel(&event_logs, &channel, callback, None);

            // Assert
            assert!(result.is_err());
            assert_eq!(result.err().unwrap(), ERROR_EVT_CHANNEL_NOT_FOUND);
        }

        #[test]
        fn it_should_not_subscribe_to_an_empty_event_logs_list() {
            // Arrange
            let callback: EVT_SUBSCRIBE_CALLBACK = Some(empty_callback);
            let channel = "Security".to_string();
            let event_logs = vec![];

            // Act
            let result = subscribe_to_channel(&event_logs, &channel, callback, None);

            // Assert
            assert!(result.is_err());
            assert_eq!(result.err().unwrap(), ERROR_EVT_INVALID_QUERY);
        }

        unsafe extern "system" fn empty_callback(
            _: EVT_SUBSCRIBE_NOTIFY_ACTION,
            _: *const c_void,
            _: isize,
        ) -> u32 {
            0
        }
    }

    mod subscription_callback {
        use super::super::*;

        #[test]
        fn it_should_abort_on_action_error() {
            // Arrange
            let action = EvtSubscribeActionError;
            let context = std::ptr::null();
            let event = 0isize;

            let buffer_vec = Vec::new();
            BUFFER.set(Mutex::new(buffer_vec));

            unsafe {
                // Act
                let result = subscription_callback(action, context, event);

                // Assert
                assert_eq!(result, 1);
            }

            let content: &Vec<u8> = &BUFFER.get().lock().unwrap();
            assert_eq!(content, &(vec![] as Vec<u8>));
        }

        #[test]
        fn it_should_abort_on_action_unknown() {
            // Arrange
            let action = EVT_SUBSCRIBE_NOTIFY_ACTION(42);
            let context = std::ptr::null();
            let event = 0isize;

            let buffer_vec = Vec::new();
            BUFFER.set(Mutex::new(buffer_vec));

            unsafe {
                // Act
                let result = subscription_callback(action, context, event);

                // Assert
                assert_eq!(result, 1);
            }

            let content: &Vec<u8> = &BUFFER.get().lock().unwrap();
            assert_eq!(content, &(vec![] as Vec<u8>));
        }

        #[test]
        fn it_should_discard_empty_events() {
            // Arrange
            let action = EvtSubscribeActionDeliver;
            let context = std::ptr::null();
            let event = 1isize;

            let buffer_vec = Vec::new();
            BUFFER.set(Mutex::new(buffer_vec));

            unsafe {
                // Act
                let result = subscription_callback(action, context, event);

                // Assert
                assert_eq!(result, 1);
            }

            let content: &Vec<u8> = &BUFFER.get().lock().unwrap();
            assert_eq!(content, &(vec![] as Vec<u8>));
        }
    }
}
