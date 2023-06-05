extern crate chrono;
extern crate git2;
use crate::*;
use chrono::Local;
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use git2::Repository;
use regex::Regex;
use std::error::Error;
use std::fs;

/// Loads a repository from the specified path.
///
/// # Arguments
///
/// * `repo_path` - A string slice that represents the path to the repository.
///
/// # Returns
///
/// Returns a `Result` containing a `Repository` if the repository is loaded successfully, or an error if the repository fails to load.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::FailLoadRepo` - Indicates that the repository failed to load.
/// * Other errors that may be returned by the underlying `Repository::open` function.
///
pub fn load_repository(repo_path: &str) -> Result<Repository, Box<dyn Error>> {
    let repo = match Repository::open(repo_path) {
        Ok(repo) => repo,
        Err(_) => {
            return Err(Box::new(CustomError::FailLoadRepo));
        }
    };

    Ok(repo)
}

/// Retrieves the name of the repository from the provided `Repository` object.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
///
/// # Returns
///
/// Returns a `Result` containing the name of the repository as a `String` if successful, or an error if the repository name is invalid or cannot be determined.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::InvalidRepoName` - Indicates that the repository name is invalid.
///
pub fn config_repo_name(repo: &Repository) -> Result<String, Box<dyn Error>> {
    let repo_path = repo.path();
    let repo_dir = repo_path.parent().ok_or(CustomError::InvalidRepoName)?;

    let repo_name = repo_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if repo_name.ends_with(".git") {
        Ok(repo_name[..repo_name.len() - 4].to_string())
    } else {
        Ok(repo_name)
    }
}

/// Traverses a tree in a repository and collects file paths and contents into a vector.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
/// * `tree` - A reference to a `Tree` object representing the tree to traverse.
/// * `path` - A string slice representing the current path in the tree.
/// * `files` - A mutable vector to store the collected file paths and contents.
///
/// # Returns
///
/// Returns `Ok(())` if the traversal is successful, or an error if an error occurs during traversal.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::ObjectNotFound` - Indicates that an object in the repository is not found.
/// * `CustomError::RepoInternalError` - Indicates an internal error in the repository.
///
pub fn traverse_tree(
    repo: &Repository,
    tree: &git2::Tree,
    path: &str,
    files: &mut Vec<(String, String)>,
) -> Result<(), Box<dyn Error>> {
    for entry in tree.iter() {
        let entry_path = format!("{}/{}", path, entry.name().unwrap());
        if entry.kind() == Some(git2::ObjectType::Blob) {
            let blob = repo
                .find_blob(entry.id())
                .map_err(|_| CustomError::ObjectNotFound)?;
            let content = String::from_utf8_lossy(blob.content());
            files.push((entry_path, content.to_string()));
        } else if entry.kind() == Some(git2::ObjectType::Tree) {
            let subtree = repo
                .find_tree(entry.id())
                .map_err(|_| CustomError::RepoInternalError)?;
            traverse_tree(repo, &subtree, &entry_path, files)?;
        }
    }
    Ok(())
}

/// Retrieves commit information from the given `Repository` and `Commit`.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
/// * `commit` - A reference to a `Commit` object representing the commit to retrieve information from.
///
/// # Returns
///
/// Returns a `Result` containing a `CommitInfo` struct if the retrieval is successful, or an error if an error occurs during the retrieval.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::InvalidRepoName` - Indicates that the repository name is invalid.
/// * `CustomError::ObjectNotFound` - Indicates that an object in the repository is not found.
/// * `CustomError::RepoInternalError` - Indicates an internal error in the repository.
///
#[allow(deprecated)]
pub fn config_commit_info(
    repo: &Repository,
    commit: &git2::Commit,
) -> Result<CommitInfo, Box<dyn Error>> {
    // Config info
    let commit_id = commit.id();
    let author = commit.author();
    let email = author.email().unwrap_or("").to_string();
    let commit_message = commit.message().unwrap_or("").to_string();
    let date = Utc.timestamp(commit.time().seconds(), 0);
    let offset = FixedOffset::west(commit.time().offset_minutes() * 60);
    let date = offset.from_utc_datetime(&date.naive_utc());
    let mut files = Vec::new();

    let repo_name = match config_repo_name(repo) {
        Ok(repo_name) => repo_name,
        Err(_) => {
            return Err(Box::new(CustomError::InvalidRepoName));
        }
    };

    // TODO
    let tags = vec![];
    let operation = "addition".to_owned();

    // Retrieve the tree of the commit
    let tree = commit.tree().map_err(|_| CustomError::ObjectNotFound)?;

    // Traverse the tree to get the file paths and content
    traverse_tree(repo, &tree, "", &mut files).map_err(|_| CustomError::RepoInternalError)?;

    let commit_info = CommitInfo {
        repo: repo_name,
        commit: commit_id,
        author: author.name().unwrap_or("").to_string(),
        email,
        commit_message,
        date,
        files,
        tags,
        operation,
    };

    Ok(commit_info)
}

/// Loads all commit IDs from the repository in topological order.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object representing the repository.
///
/// # Returns
///
/// Returns a `Result` containing a vector of commit IDs (`Vec<String>`) if the operation is successful, or an error if an error occurs during the process.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::AccessWalkerError` - Indicates an error occurred while accessing the revision walker.
/// * `CustomError::PushWalkerHeadError` - Indicates an error occurred while pushing the head commit to the revision walker or setting the sorting order.
/// * `CustomError::WalkerSortError` - Indicates an error occurred while sorting the revision walker.
/// * `CustomError::RepoCommitError` - Indicates an error occurred while finding a commit in the repository.
///
pub fn load_all_commits(repo: &Repository) -> Result<Vec<String>, Box<dyn Error>> {
    let mut revwalk = repo.revwalk().map_err(|_| CustomError::AccessWalkerError)?;

    revwalk
        .push_head()
        .map_err(|_| CustomError::PushWalkerHeadError)?;
    revwalk
        .set_sorting(git2::Sort::TOPOLOGICAL)
        .map_err(|_| CustomError::PushWalkerHeadError)?;

    let mut commits = Vec::new();

    for oid in revwalk {
        let oid = oid.map_err(|_| CustomError::WalkerSortError)?;
        let commit = repo
            .find_commit(oid)
            .map_err(|_| CustomError::RepoCommitError)?;
        let commit_id = commit.id().to_string();
        commits.push(commit_id);
    }

    Ok(commits)
}

/// Loads a subset of commits based on specified conditions.
///
/// This function takes optional start and end commit IDs, along with a slice of commit IDs.
/// It returns a vector containing a subset of the input commits, starting from the specified
/// start commit (inclusive) and ending at the specified end commit (inclusive).
///
/// # Arguments
///
/// * `commit_from` - An optional string representing the start commit ID.
/// * `commit_to` - An optional string representing the end commit ID.
/// * `commits` - A slice of strings representing the available commit IDs.
///
/// # Returns
///
/// Returns a vector of commit IDs as strings, representing the subset of commits based on
/// the specified conditions. If the start commit is after the end commit or if either commit
/// is not found in the input commits, an empty vector is returned.
///
pub fn load_commits_by_conditions(
    commit_from: Option<String>,
    commit_to: Option<String>,
    commits: &[String],
) -> Vec<String> {
    match (commit_from, commit_to) {
        (Some(start_commit), Some(end_commit)) => {
            let start_index = commits.iter().position(|commit| *commit == start_commit);
            let end_index = commits.iter().position(|commit| *commit == end_commit);

            if let (Some(start), Some(end)) = (start_index, end_index) {
                if start <= end {
                    commits[start..=end].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Loads all commit IDs from the given `Repository`.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
///
/// # Returns
///
/// Returns a `Result` containing a vector of commit IDs as strings if the loading is successful, or an error if an error occurs during the loading.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::AccessWalkerError` - Indicates an error in accessing the commit walker.
/// * `CustomError::PushWalkerHeadError` - Indicates an error in pushing the head to the commit walker.
/// * `CustomError::WalkerSortError` - Indicates an error in sorting the commit walker.
/// * `CustomError::RepoCommitError` - Indicates an error in finding a commit in the repository.
///
pub fn load_all_object_ids(repo: &Repository) -> Result<Vec<git2::Oid>, Box<dyn Error>> {
    let mut object_ids = Vec::new();
    let odb = repo.odb().map_err(|_| CustomError::ObjectNotAccess)?;

    odb.foreach(|id| {
        object_ids.push(*id);
        true
    })
    .map_err(|_| CustomError::RepoInternalError)?;

    Ok(object_ids)
}

/// Parses a date string into a `DateTime<Utc>` object.
///
/// # Arguments
///
/// * `input` - A string slice representing the date to parse. The expected format is "%Y-%m-%d".
/// * `mytype` - A string slice indicating the type of datetime to create. It can be either "start" or any other value.
///
/// # Returns
///
/// Returns a `Result` containing a `DateTime<Utc>` object if the parsing is successful, or an error if an error occurs during the parsing.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::InvalidDateFormat` - Indicates that the input date format is invalid.
/// * `CustomError::InvalidTimeFormat` - Indicates that the time format is invalid.
///
pub fn parse_date_to_datetime(input: &str, mytype: &str) -> Result<DateTime<Utc>, Box<dyn Error>> {
    let date =
        NaiveDate::parse_from_str(input, "%Y-%m-%d").map_err(|_| CustomError::InvalidDateFormat)?;

    let time: NaiveTime;
    if mytype == "start" {
        if let Some(t) = NaiveTime::from_hms_opt(0, 0, 0) {
            time = t;
        } else {
            return Err(Box::new(CustomError::InvalidTimeFormat));
        }
    } else if let Some(t) = NaiveTime::from_hms_opt(23, 59, 59) {
        time = t;
    } else {
        return Err(Box::new(CustomError::InvalidTimeFormat));
    }

    let datetime = NaiveDateTime::new(date, time);
    let datetime_utc = DateTime::from_utc(datetime, Utc);
    Ok(datetime_utc)
}

/// Checks if the input string has a valid date format of "YYYY-MM-DD".
///
/// # Arguments
///
/// * `input` - The string to be checked for date format validity.
///
/// # Returns
///
/// Returns `true` if the input string has a valid date format, otherwise `false`.
pub fn is_valid_date_format(input: &str) -> bool {
    if let Ok(date) = NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        let formatted = date.format("%Y-%m-%d").to_string();
        return formatted == input;
    }
    false
}

/// Loads the content of a configuration file (`.gitleaks.toml` or `gitleaks.toml`) from the target repository.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object representing the target repository.
///
/// # Returns
///
/// Returns a `Result` containing an `Option<String>` with the content of the configuration file if found, or `None` if the configuration file is not found in any commit.
///
/// # Errors
///
/// This function may return an error if any error occurs during the repository traversal or object retrieval.
///
pub fn load_config_content_from_target_repo(
    repo: &Repository,
) -> Result<Option<String>, Box<dyn Error>> {
    let head_commit = repo.head()?.peel_to_commit()?;
    let mut walker = repo.revwalk()?;
    walker.push(head_commit.id())?;

    // Iterate over all commits in the repository
    for commit_id in walker {
        let commit = repo.find_commit(commit_id?)?;
        let tree = commit.tree()?;

        // Iterate over all entries in the tree
        for entry in tree.iter() {
            let file_name = entry.name().unwrap_or("");
            if file_name == ".gitleaks.toml" || file_name == "gitleaks.toml" {
                let blob = entry.to_object(repo)?.peel_to_blob()?;
                let content = String::from_utf8_lossy(blob.content());
                return Ok(Some(content.into()));
            }
        }
    }

    Ok(None)
}

/// Extracts the repository name from a given URL.
///
/// # Arguments
///
/// * `url` - A string slice representing the URL of the repository.
///
/// # Returns
///
/// Returns an `Option<String>` containing the extracted repository name if it matches the expected format, or `None` if the extraction fails.
///
pub fn extract_repo_name(url: &str) -> Option<String> {
    let re = Regex::new(r"/([^/]+)\.git$").unwrap();
    if let Some(captures) = re.captures(url) {
        if let Some(repo_name) = captures.get(1) {
            return Some(repo_name.as_str().to_string());
        }
    }
    None
}

/// Clones or loads a repository based on the provided configuration.
///
/// # Arguments
///
/// * `config` - A reference to a `Config` object containing the repository information.
///
/// # Returns
///
/// Returns a `Result` containing a `Repository` object if the operation is successful, or an error if an error occurs during cloning or loading.
///
/// # Errors
///
/// This function may return the following errors:
///
/// * `CustomError::FailDeteleDir` - Indicates that the directory removal operation failed.
/// * `CustomError::FailCreateDir` - Indicates that the directory creation operation failed.
/// * `CustomError::FailCloneRepo` - Indicates that the repository cloning operation failed.
/// * `CustomError::FailLoadRepo` - Indicates that the repository loading operation failed.
///
#[warn(clippy::needless_return)]
pub fn clone_or_load_repository(config: &Config) -> Result<Repository, Box<dyn Error>> {
    if is_link(&config.repo) {
        let repo_path = match &config.disk {
            Some(disk) => disk.to_string(),
            None => {
                let dest = "workplace/";
                let mut repo_path = String::new();
                if let Some(name) = extract_repo_name(&config.repo) {
                    repo_path = format!("{}{}", dest, name);
                }

                if fs::metadata(&repo_path).is_ok() {
                    match fs::remove_dir_all(&repo_path) {
                        Ok(_) => {}
                        Err(_) => {
                            return Err(Box::new(CustomError::FailDeleteDir));
                        }
                    }
                }

                match fs::create_dir(&repo_path) {
                    Ok(_) => {}
                    Err(_) => {
                        return Err(Box::new(CustomError::FailCreateDir));
                    }
                }
                repo_path
            }
        };
        match Repository::clone(&config.repo, repo_path) {
            Ok(repo) => {
                println!(
                    "\x1b[34m[INFO]\x1b[0m[{}] Clone repo ...",
                    Local::now().format("%Y-%m-%d %H:%M:%S"),
                );

                Ok(repo)
            }
            Err(_) => Err(Box::new(CustomError::FailCloneRepo)),
        }
    } else {
        match load_repository(&config.repo) {
            Ok(repo) => {
                println!(
                    "\x1b[34m[INFO]\x1b[0m[{}] Clone repo ...",
                    Local::now().format("%Y-%m-%d %H:%M:%S"),
                );

                Ok(repo)
            }

            Err(_) => Err(Box::new(CustomError::FailLoadRepo)),
        }
    }
}

// NOTE: The commented-out function can be tested after specifying the repo file
#[cfg(test)]
mod tests {

    use super::*;
    // static VALID_PATH: &str = "D:/Workplace/Git/TestGitOperation";
    // static INVALID_PATH: &str = "D:/Workplace/Git/TestGitOperation222";

    // // test load_repository
    // #[test]
    // fn test_load_repository_valid_path() {
    //     let result = load_repository(VALID_PATH);
    //     assert!(result.is_ok());
    // }

    // #[test]
    // fn test_load_repository_invalid_path() {
    //     let result = load_repository(INVALID_PATH);
    //     assert!(result.is_err());
    // }

    // NOTE: The commented-out function can be tested after specifying the repo file
    // // test config_repo_name
    // #[test]
    // fn test_config_repo_name_valid_repo() {
    //     let repo = match load_repository(VALID_PATH) {
    //         Ok(repo) => repo,
    //         Err(_) => {
    //             panic!("Failed to load repository");
    //         }
    //     };
    //     let result = match config_repo_name(&repo) {
    //         Ok(result) => result,
    //         Err(e) => {
    //             panic!("Error:{}", e);
    //         }
    //     };
    //     assert_eq!(result, "TestGitOperation");
    // }

    // // test load_all_commits
    // #[test]
    // fn test_load_all_commits_valid_repository() {
    //     let repo = match Repository::init(VALID_PATH) {
    //         Ok(repo) => repo,
    //         Err(e) => {
    //             eprintln!("{}", e);
    //             panic!("Failed to initialize repository");
    //         }
    //     };

    //     let result = load_all_commits(&repo);

    //     assert!(result.is_ok());
    //     let commits = result.unwrap();
    //     assert!(commits.contains(&"9e2fe5fc27b1bb8bd4de5574f8d9010164427051".to_string()));
    // }

    // // test load_commits_by_conditions
    // #[test]
    // fn test_load_commits_by_conditions_valid_conditions() {
    //     let commits = vec![
    //         "commit1".to_string(),
    //         "commit2".to_string(),
    //         "commit3".to_string(),
    //         "commit4".to_string(),
    //         "commit5".to_string(),
    //     ];
    //     let commit_from = Some("commit2".to_string());
    //     let commit_to = Some("commit4".to_string());

    //     let result = load_commits_by_conditions(commit_from, commit_to, &commits);

    //     assert_eq!(
    //         result,
    //         vec![
    //             "commit2".to_string(),
    //             "commit3".to_string(),
    //             "commit4".to_string(),
    //         ]
    //     );
    // }

    // // test load_all_object_ids
    // #[test]
    // fn test_load_all_object_ids_valid_repository() {
    //     let repo = match Repository::init(VALID_PATH) {
    //         Ok(repo) => repo,
    //         Err(e) => {
    //             eprintln!("{}", e);
    //             panic!("Failed to initialize repository");
    //         }
    //     };

    //     let oid1 = repo.blob("Content 1".as_bytes()).unwrap();
    //     let oid2 = repo.blob("Content 2".as_bytes()).unwrap();
    //     let oid3 = repo.blob("Content 3".as_bytes()).unwrap();

    //     let result = load_all_object_ids(&repo);

    //     assert!(result.is_ok());
    //     let object_ids = result.unwrap();
    //     assert!(object_ids.contains(&oid1));
    //     assert!(object_ids.contains(&oid2));
    //     assert!(object_ids.contains(&oid3));
    // }

    // test parse_date_to_datetime
    #[test]
    fn test_parse_date_to_datetime_valid_input_start() {
        let valid_input = "2023-05-25";
        let mytype = "start";
        let result = parse_date_to_datetime(valid_input, mytype);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_rfc3339(), "2023-05-25T00:00:00+00:00");
    }

    #[test]
    fn test_parse_date_to_datetime_valid_input_end() {
        let valid_input = "2023-05-25";
        let mytype = "end";
        let result = parse_date_to_datetime(valid_input, mytype);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_rfc3339(), "2023-05-25T23:59:59+00:00");
    }

    #[test]
    fn test_parse_date_to_datetime_invalid_input() {
        let invalid_input = "2023-05-32";
        let mytype = "start";
        let result = parse_date_to_datetime(invalid_input, mytype);
        assert!(result.is_err());
    }

    // test is_valid_date_format
    #[test]
    fn test_is_valid_date_format_valid_input() {
        let valid_input = "2023-05-25";
        let result = is_valid_date_format(valid_input);
        assert!(result);
    }

    #[test]
    fn test_is_valid_date_format_invalid_input() {
        let invalid_input = "2023-05-32";
        let result = is_valid_date_format(invalid_input);
        assert!(!result);
    }


    // test extract_repo_name
    #[test]
    fn test_extract_repo_name() {
        // Test with a valid URL
        let url = "https://github.com/user/repo.git";
        let result = extract_repo_name(url);
        assert_eq!(result, Some("repo".to_owned()));

        // Test with a URL without ".git" extension
        let url = "https://github.com/user/repo";
        let result = extract_repo_name(url);
        assert_eq!(result, None);

    }
}
