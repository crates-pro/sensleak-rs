/// Represents various error types that can occur in the application.
#[derive(Debug, PartialEq)]
pub enum MyError {
    FileNotFound,
    InvalidTomlFile,
    NetworkError,
    InternalError,
    FailToWriteError,
    MissingAllowlist,
    ApplicationError
}

impl MyError {
    /// Returns a message describing the error.
    pub fn message(&self) -> &'static str {
        match *self {
            MyError::FileNotFound => "File not found!",
            MyError::InvalidTomlFile => "Failed to parse the file, it is not an invalid toml file!",
            MyError::NetworkError => "Network error!",
            MyError::InternalError => "Internal error!",
            MyError::FailToWriteError => "Failed to write to file!",
            MyError::MissingAllowlist =>"Missing [allowlist]!",
            MyError::ApplicationError=>"Application Error!",
        }
    }
}
