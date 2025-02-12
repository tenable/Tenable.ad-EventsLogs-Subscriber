pub const EMPTY_STRING: &str = "";
pub const NAME: &str = "Name";
pub const TIME_CREATED: &str = "TimeCreated";
pub const SYSTEM_TIME: &str = "SystemTime";
pub const DATE_TIME_FORMAT: &str = "%Y%m%d%H%M%S%.6f-000";
pub const EXECUTION: &str = "Execution";
pub const PROCESS_ID: &str = "ProcessID";
pub const THREAD_ID: &str = "ThreadID";
pub const QUOTE: &str = "\"";
// Define insertion string list delimiter
// We currently use the following sequence: \u001F\u001E
// which contains the Unit Separator and the Record Separator character
// and should never appear in an insertion string.
pub const DATA_DELIMITER: &str = "\u{1f}\u{1e}";
pub const FILETIME_TO_UNIX_EPOCH_SECS: i64 = 11_644_473_600;
/// Compile time constant to retrieve the package version for inclusion in logs/gz archive
pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
