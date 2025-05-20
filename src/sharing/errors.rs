#[derive(Debug, Eq, PartialEq)]
pub enum FileSharingFailureReason {
    SetupError,
    ConnectionError,
    MandatoryPrerequisitesNotFilled,
    FileTransferFailed,
    DisableError,
}

#[derive(Debug, Eq, PartialEq)]
pub struct FileSharingError {
    pub(crate) error: FileSharingFailureReason,
    pub(crate) description: String,
}