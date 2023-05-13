pub use config::Config;
pub use file_utils::{read_allowlist,is_file_in_whitelist,read_ruleslist,contains_keyword,is_path_in_allowlist};
mod file_utils;
mod config;
pub mod detect_service;
