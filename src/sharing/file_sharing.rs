use crate::sharing::errors::FileSharingError;
use crate::configuration::{Arguments, EventsLogsConfiguration};

#[cfg_attr(test, mockall::automock)]
pub trait FileSharing {
    fn new(args: &Arguments, configuration: &EventsLogsConfiguration) -> Self where Self: Sized;
    fn set_is_pdc(&mut self, is_pdc: bool);
    fn setup(&mut self) -> Result<(), FileSharingError>;
    fn disable(&mut self) -> Result<(), FileSharingError>;
    /// Write the file thanks to the underlying file sharing implementation
    ///
    /// The function will return the location where it wrote the file on success or return a specific error
    fn try_flush_events_to_file(&mut self, file_path: &String, file_content: &Vec<u8>) -> Result<String, FileSharingError>;
    fn on_configuration_change(&mut self, updated_configuration: &EventsLogsConfiguration);
}

#[derive(PartialEq, Eq, Debug)]
pub enum FileSharingMode {
    SMB,
    SYSVOL,
}