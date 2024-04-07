use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::service::detect_service::detect;
use crate::{Config, Leak};

/// The scan configuration
#[derive(Deserialize, Serialize, ToSchema)]
pub struct ConfigDto {
    /// Target repository.
    pub repo: String,
    /// Config path
    pub config: String,
    /// Maximum number of threads sensleak spawns
    pub report: Option<String>,
    /// The number of git files processed in each batch
    pub report_format: Option<String>,
    /// Path to write json leaks file.
    pub repo_config: Option<bool>,
    /// json, csv, sarif
    pub threads: Option<usize>,
    /// Show verbose output from scan.
    pub chunk: Option<usize>,
    /// Pretty print json if leaks are present.
    pub commit: Option<String>,
    /// comma separated list of a commits to scan
    pub commits: Option<String>,
    /// file of new line separated list of a commits to scan
    pub commits_file: Option<String>,
    /// Scan commits more recent than a specific date. Ex: '2006-01-02' or '2023-01-02T15:04:05-0700' format.
    pub commit_since: Option<String>,
    /// Scan commits older than a specific date. Ex: '2006-01-02' or '2006-10-02T15:04:05-0700' format.
    pub commit_until: Option<String>,

    /// Commit to start scan from
    pub commit_from: Option<String>,
    /// Commit to stop scan
    pub commit_to: Option<String>,
    /// Branch to scan
    pub branch: Option<String>,
    /// Run sensleak on uncommitted code
    pub uncommitted: Option<bool>,
    /// Set user to scan
    pub user: Option<String>,

    /// Clones repo(s) to disk.
    pub disk: Option<String>,

    /// Output to database
    pub to_db: bool,
}

/// The return results of the scan.
#[derive(Deserialize, Serialize, ToSchema)]
pub struct ScanResponse {
    /// 200-success, 400-fail
    code: usize,
    /// the leaks number
    leaks_number: Option<usize>,
    /// the number of scanned commits
    commits_number: Option<usize>,
    /// leaks
    leaks: Option<Vec<Leak>>,
    /// message
    message: Option<String>,
}

/// Scan the repo.
///
/// Scan Git repositories for sensitive data.
#[utoipa::path(
    post,
    path = "/scan",
    request_body = ConfigDto,
    responses(
        (status = 200, description = "success", body = ScanResponse),
        (status = 400, description = "fail", body = ScanResponse)
    )
)]
pub async fn scan_repo(Json(json_config): Json<ConfigDto>) -> Json<ScanResponse> {
    let mut config: Config = Default::default();
    config.repo = json_config.repo;
    config.config = json_config.config;
    config.report = json_config.report;
    config.threads = json_config.threads;
    config.chunk = json_config.chunk;
    config.report_format = json_config.report_format;
    config.commit = json_config.commit;
    config.commits = json_config.commits;
    config.commit_from = json_config.commit_from;
    config.commit_to = json_config.commit_to;
    config.commit_since = json_config.commit_since;
    config.commits_file = json_config.commits_file;
    config.branch = json_config.branch;
    config.uncommitted = false;
    config.user = json_config.user;
    config.disk = json_config.disk;
    config.repo_config = json_config.repo_config.unwrap_or(false);
    config.to_db = json_config.to_db;

    match detect(config).await {
        Ok(results) => Json(ScanResponse {
            code: 200,
            leaks_number: Some(results.outputs.len()),
            commits_number: Some(results.commits_number),
            leaks: Some(results.outputs),
            message: None,
        }),
        Err(err) => Json(ScanResponse {
            code: 400,
            message: Some(err.to_string()),
            leaks_number: None,
            commits_number: None,
            leaks: None,
        }),
    }
}



#[cfg(test)]
mod tests {
    // use super::*;
    // use axum::{
    //     extract::Json,
 
    // };
    

    // #[tokio::test]
    // async fn test_scan_repo_success() {
    //     let config = ConfigDto {
    //         repo: String::from("example/repo"),
    //         config: String::from("example/config"),
    //         report: Some(String::from("example/report")),
    //         report_format: Some(String::from("json")),
    //         repo_config: Some(true),
    //         threads: Some(4),
    //         chunk: Some(10),
    //         commit: Some(String::from("abcd1234")),
    //         commits: Some(String::from("commit1,commit2")),
    //         commits_file: Some(String::from("path/to/file")),
    //         commit_since: Some(String::from("2023-01-01")),
    //         commit_until: Some(String::from("2023-01-31")),
    //         commit_from: Some(String::from("abcd1234")),
    //         commit_to: Some(String::from("efgh5678")),
    //         branch: Some(String::from("main")),
    //         uncommitted: Some(false),
    //         user: Some(String::from("john")),
    //         disk: Some(String::from("path/to/disk")),
    //     };

    //     let json_config = Json(config);
    //     let response = scan_repo(json_config).await;
        
    //     assert_eq!(response.code, 200);
    //     assert_eq!(response.leaks_number, Some(10));
    //     assert_eq!(response.commits_number, Some(2));
    //     assert_eq!(response.message, None);
   
    // }
}