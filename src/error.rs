/// Represents various error types that can occur in the application.
#[derive(Debug, PartialEq)]
pub enum MyError {
    ConfigFileNotFound,
    InvalidTomlFile,
    NetworkError,
    InternalError,
    FailToWriteError,
    MissingAllowlist,
    ApplicationError,


    InvalidRepoError,
    RepoInternalError,
    RepoCommitError,
    InvalidDateFormat,
    InvalidTimeFormat
     
}

impl MyError {
    /// Returns a message describing the error.
    pub fn message(&self) -> &'static str {
        match *self {
            MyError::ConfigFileNotFound => "Fail to load the config file: File not found!",
            MyError::InvalidTomlFile => "Failed to parse the file, it is not an invalid toml file!",
            MyError::NetworkError => "Network error!",
            MyError::InternalError => "Internal error!",
            MyError::FailToWriteError => "Failed to write to file!",
            MyError::MissingAllowlist =>"Missing [allowlist]!",
            MyError::ApplicationError=>"Application Error!",
            MyError::InvalidRepoError=>"Invalid Repository! Fail to open the repository!",
            MyError::RepoInternalError=>"Internal error in repository",
            MyError::RepoCommitError=>"Fail to deal with the commits in repository",
            MyError::InvalidDateFormat=>"Invalid date format!",
            MyError::InvalidTimeFormat=>"Invalid time format!",
        }
    }
}
#[derive(Debug, PartialEq)]
pub enum RepoError {
    InvalidRepoError,
    RepoInternalError,
    ObjectNotFound,
    ObjectNotAccess,
    AccessWalkerError,
    RepoCommitError,
    PushWalkerHeadError,
    WalkerSortError,
    
     
}

impl RepoError {
    /// Returns a message describing the error.
    pub fn message(&self) -> &'static str {
        match *self {
            RepoError::InvalidRepoError=>"Invalid Repository!",
            RepoError::RepoInternalError=>"Internal error within the repository!",
            RepoError::ObjectNotFound=>"Failure to find a blob or tree object in the repository!",
            RepoError::ObjectNotAccess=>"Fail to access the repository's object database.!",
            RepoError::AccessWalkerError=>"Failure to create or access the revision walker!",
            RepoError::RepoCommitError=>"Fail to find a commit in the repository.",
            RepoError::WalkerSortError=>"Fail to set the sorting order of the revision walker.!",
            RepoError::PushWalkerHeadError=>"Fail to push the HEAD reference to the revision walker!",
            
        }
    }
}
impl std::error::Error for RepoError {}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}
// #[derive(Debug, PartialEq)]
// pub enum DateTimeUtilsError {
//     InvalidDateFormat,
//     InvalidTimeFormat
     
// }

// impl RepoError {
//     /// Returns a message describing the error.
//     pub fn message(&self) -> &'static str {
//         match *self {
//             DateTimeUtilsError::InvalidDateFormat=>"Invalid date format!",
//             DateTimeUtilsError::InvalidTimeFormat=>"Invalid time format!",
            
//         }
//     }
// }