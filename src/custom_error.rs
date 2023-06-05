use std::error::Error;
use std::fmt;

/// CustomError represents custom errors that can occur in the application.
#[derive(Debug)]
pub enum CustomError {
    FailDeleteDir,
    FailCreateDir,
    FailLoadRepo,
    FailCloneRepo,
    InvalidRepoName,
    ObjectNotFound,
    RepoInternalError,
    ObjectNotAccess,
    ObjectConvertFail,
    AccessWalkerError,
    RepoCommitError,
    WalkerSortError,
    PushWalkerHeadError,
    InvalidDateFormat,
    InvalidTimeFormat,
    InvalidTomlFile,
}

impl fmt::Display for CustomError {
    /// Formats the error message for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_message = match *self {
            CustomError::FailDeleteDir => "Failed to delete directory",
            CustomError::FailCreateDir => "Failed to create directory",
            CustomError::FailLoadRepo => "Failed to load repository",
            CustomError::FailCloneRepo => "Failed to clone repository",
            CustomError::InvalidRepoName => "Invalid repository name",
            CustomError::RepoInternalError => "Internal error within the repository",
            CustomError::ObjectNotFound => "Failure to find a blob or tree object in the repository",
            CustomError::ObjectNotAccess => "Failed to access the repository's object database",
            CustomError::ObjectConvertFail => "Failed to convert object to commit",
            CustomError::AccessWalkerError => "Failure to create or access the revision walker",
            CustomError::RepoCommitError => "Failed to find a commit in the repository",
            CustomError::WalkerSortError => "Failed to set the sorting order of the revision walker",
            CustomError::PushWalkerHeadError => "Failed to push the HEAD reference to the revision walker",
            CustomError::InvalidDateFormat => "Invalid date format",
            CustomError::InvalidTimeFormat => "Invalid time format",
            CustomError::InvalidTomlFile => "Invalid TOML file",
        };
        write!(f, "{}", error_message)
    }
}

impl Error for CustomError {}
