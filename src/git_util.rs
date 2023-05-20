extern crate chrono;
extern crate git2;
use crate::*;
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use git2::{ Repository};
use crate::error::{MyError,RepoError};
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

/// Loads a Git repository from the specified path.
///
/// This function attempts to open a Git repository located at the given `repo_path` and returns
/// a `Repository` object representing the repository if successful.
///
/// # Arguments
///
/// * `repo_path` - A string slice representing the path to the Git repository.
///
/// # Returns
///
/// Returns a `Result` containing the opened `Repository` object if successful, or an `Err` variant
/// of the custom `RepoError` type if the repository cannot be opened or is invalid.
///
/// # Errors
///
/// This function can return an `Err` variant of the `RepoError` enum in the following case:
///
/// * Failure to open the Git repository at the specified `repo_path`.
///
pub fn load_repository(repo_path: &str) -> Result<Repository, RepoError> {
    let repo = match Repository::open(repo_path) {
        Ok(repo) => {
            repo
        }
        Err(_) => {
            return Err(RepoError::InvalidRepoError);
        }
    };

    Ok(repo)
}

/// Extracts the name of the repository from its path.
///
/// This function takes a `Repository` object and retrieves the name of the repository
/// by extracting it from the parent directory of the repository's path. If the repository
/// name ends with ".git", the suffix is removed before returning the name.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
///
/// # Returns
///
/// Returns a `Result` containing the repository name as a `String`, or an `Err` variant
/// of the custom `RepoError` type in case of an error.
///
/// # Errors
///
/// This function can return an `Err` variant of the `RepoError` enum in the following cases:
///
/// * The repository's path is invalid or does not have a parent directory.
pub fn config_repo_name(repo: &Repository) -> Result<String, RepoError> {
    let repo_path = repo.path();
    // let repo_dir = repo_path
    //     .parent()
    //     .ok_or_else(|| RepoError::InvalidRepoError)?;
    let repo_dir = repo_path
    .parent()
    .ok_or(RepoError::InvalidRepoError)?;

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

/// Recursively traverses a Git tree and extracts the paths and contents of blobs.
///
/// This function takes a `Repository` object, a reference to a `git2::Tree`, a path string,
/// and a mutable `Vec` of tuples representing file paths and their contents. It recursively
/// explores the tree and its subtrees, adding the paths and contents of blobs to the `files`
/// vector.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
/// * `tree` - A reference to a `git2::Tree`.
/// * `path` - The path of the current tree or subtree.
/// * `files` - A mutable `Vec` of `(String, String)` tuples to store the file paths and contents.
///
/// # Returns
///
/// Returns `Ok(())` if the traversal completes successfully, or an `Err` variant of the custom
/// `RepoError` type in case of an error.
///
/// # Errors
///
/// This function can return an `Err` variant of the `RepoError` enum in the following cases:
///
/// * Failure to find a blob or tree object in the repository.
/// * Internal error within the repository.
///
pub fn traverse_tree(repo: &Repository,tree: &git2::Tree,path: &str,files: &mut Vec<(String, String)>,) -> Result<(), RepoError> {
    for entry in tree.iter() {
        let entry_path = format!("{}/{}", path, entry.name().unwrap());
        if entry.kind() == Some(git2::ObjectType::Blob) {
            let blob = repo.find_blob(entry.id())
                .map_err(|_| RepoError::ObjectNotFound)?;
            let content = String::from_utf8_lossy(blob.content());
            files.push((entry_path, content.to_string()));
        } else if entry.kind() == Some(git2::ObjectType::Tree) {
            let subtree = repo.find_tree(entry.id())
                .map_err(|_| RepoError::RepoInternalError)?;
            traverse_tree(repo, &subtree, &entry_path, files)?;
        }
    }
    Ok(())
}

/// Retrieves the commit information from the given repository and commit.
///
/// This function extracts various information from the commit, such as the commit ID, author,
/// email, commit message, date, and file paths. It returns a `CommitInfo` struct containing
/// all the extracted information.
///
/// # Arguments
///
/// * `repo` - A reference to the repository from which to retrieve the commit information.
/// * `commit` - A reference to the commit for which to retrieve the information.
///
/// # Errors
///
/// This function can return a `RepoError` if any of the following conditions occur:
///
/// * `config_repo_name` fails to retrieve the repository name.
/// * The commit's tree cannot be retrieved, resulting in `ObjectNotFound` error.
/// * An error occurs during the traversal of the commit's tree, resulting in `RepoInternalError`.
///
#[allow(deprecated)]
pub fn config_commit_info(repo: &Repository, commit: &git2::Commit) -> Result<CommitInfo, RepoError> {
    // Config info
    let commit_id = commit.id();
    let author = commit.author();
    let email = author.email().unwrap_or("").to_string();
    let commit_message = commit.message().unwrap_or("").to_string();
    let date = Utc.timestamp(commit.time().seconds(), 0);
    let offset = FixedOffset::west(commit.time().offset_minutes() * 60);
    let date = offset.from_utc_datetime(&date.naive_utc());
    let mut files = Vec::new();
    let repo_name = config_repo_name(repo)?;

    // TODO
    let tags = vec![];
    let operation = "addition".to_owned();

    // Retrieve the tree of the commit
    let tree = commit.tree().map_err(|_| RepoError::ObjectNotFound)?;

    // Traverse the tree to get the file paths and content
    traverse_tree(repo, &tree, "", &mut files).map_err(|_| RepoError::RepoInternalError)?;

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

/// Loads all commit IDs in the repository.
///
/// This function retrieves all commit IDs in the repository by performing a topological
/// traversal of the commit history. The commit IDs are returned as a vector of strings.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
///
/// # Returns
///
/// Returns a `Result` containing a vector of commit IDs as strings, or an `Err` variant
/// of the custom `RepoError` type in case of an error.
///
/// # Errors
///
/// This function can return an `Err` variant of the `RepoError` enum in the following cases:
///
/// * Failure to create or access the revision walker.
/// * Failure to push the HEAD reference to the revision walker.
/// * Failure to set the sorting order of the revision walker.
/// * Failure to find a commit in the repository.
///
pub fn load_all_commits(repo: &Repository) -> Result<Vec<String>, RepoError> {
    let mut revwalk = repo.revwalk()
        .map_err(|_| RepoError::AccessWalkerError)?;
    
    revwalk.push_head()
        .map_err(|_| RepoError::PushWalkerHeadError)?;
    revwalk.set_sorting(git2::Sort::TOPOLOGICAL)
        .map_err(|_| RepoError::PushWalkerHeadError)?;
    
    let mut commits = Vec::new();
    
    for oid in revwalk {
        let oid = oid
            .map_err(|_| RepoError::WalkerSortError)?;
        let commit = repo.find_commit(oid)
            .map_err(|_| RepoError::RepoCommitError)?;
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
pub fn load_commits_by_conditions(commit_from: Option<String>, commit_to: Option<String>, commits: &[String]) -> Vec<String> {
    match (commit_from, commit_to) {
        (Some(start_commit), Some(end_commit)) => {
            let start_index = commits.iter().position(|commit| *commit == start_commit);
            let end_index = commits.iter().position(|commit| *commit == end_commit);

            if let (Some(start), Some(end)) = (start_index, end_index) {
                if start <= end {
                    commits[start..=end].to_vec()
                } else {
                    Vec::new() // Return an empty vector if start_commit is after end_commit
                }
            } else {
                Vec::new() // Return an empty vector if either commit is not found
            }
        }
        _ => Vec::new(), // Return an empty vector if either commit_from or commit_to is None
    }
}

/// Loads all object IDs in the repository.
///
/// This function retrieves all object IDs in the repository's object database and returns them
/// as a vector of `Oid` values.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object.
///
/// # Returns
///
/// Returns a `Result` containing a vector of `Oid` values, representing all the object IDs
/// in the repository's object database, or an `Err` variant of the custom `RepoError` type
/// in case of an error.
///
/// # Errors
///
/// This function can return an `Err` variant of the `RepoError` enum in the following cases:
///
/// * Failure to access the repository's object database.
/// * Internal error within the repository.
///
pub fn load_all_object_ids(repo: &Repository) -> Result<Vec<git2::Oid>, RepoError> {
    let mut object_ids = Vec::new();
    let odb = repo.odb()
        .map_err(|_| RepoError::ObjectNotAccess)?;

    odb.foreach(|id| {
        object_ids.push(*id);
        true
    })
    .map_err(|_| RepoError::RepoInternalError)?;

    Ok(object_ids)
}

/// Parses a date string into a UTC `DateTime` with a specified time type.
///
/// This function takes a date string in the format "%Y-%m-%d" and a time type string
/// indicating whether it is a "start" or "end" time. It returns a `DateTime<Utc>`
/// representing the combined date and time in UTC.
///
/// # Arguments
///
/// * `input` - A string slice representing the date to parse in the format "%Y-%m-%d".
/// * `mytype` - A string slice indicating the type of time: "start" or "end".
///
/// # Returns
///
/// Returns a `Result` containing a `DateTime<Utc>` if the parsing is successful, or an
/// `Err` variant of the custom `MyError` type in case of an invalid date format or time format.
///
/// # Errors
///
/// This function can return an `Err` variant of the `MyError` enum in the following cases:
///
/// * Invalid date format provided.
/// * Invalid time format provided.
///
pub fn parse_date_to_datetime(input: &str, mytype: &str) -> Result<DateTime<Utc>, MyError> {
    let date = NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|_| MyError::InvalidDateFormat)?;
    
    let time: NaiveTime;
    if mytype == "start" {
        if let Some(t) = NaiveTime::from_hms_opt(0, 0, 0) {
            time = t;
        } else {
            return Err(MyError::InvalidTimeFormat);
        }
    } else if let Some(t) = NaiveTime::from_hms_opt(23, 59, 59) {
            time = t;
        } else {
            return Err(MyError::InvalidTimeFormat);
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
 // NOTE: The commented-out function can be tested after specifying the repo file
#[cfg(test)]
mod tests {

    use super::*;
    static VALID_PATH: &str = "tests/TestGitOperation";
    static INVALID_PATH: &str = "tests/TestGitOperation1";


    // test load_repository
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
    //         Err(e) => {
    //             eprintln!("{}", e.message());
    //             panic!("Failed to load repository");
    //         }
    //     };
    //     let result = config_repo_name(&repo);
    //     assert_eq!(result, Ok("TestGitOperation".to_string()));
    // }
    
    // test load_all_commits
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
    
    // test load_commits_by_conditions
    #[test]
    fn test_load_commits_by_conditions_valid_conditions() {
        let commits = vec![
            "commit1".to_string(),
            "commit2".to_string(),
            "commit3".to_string(),
            "commit4".to_string(),
            "commit5".to_string(),
        ];
        let commit_from = Some("commit2".to_string());
        let commit_to = Some("commit4".to_string());

        let result = load_commits_by_conditions(commit_from, commit_to, &commits);

        assert_eq!(result, vec![
            "commit2".to_string(),
            "commit3".to_string(),
            "commit4".to_string(),
        ]);
    }
   
    // test load_all_object_ids
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
        assert_eq!(result.unwrap_err(), MyError::InvalidDateFormat);
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
}
