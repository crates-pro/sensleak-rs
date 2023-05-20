extern crate chrono;
extern crate git2;
use crate::*;
use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use git2::BranchType;
use git2::{Repository};
use std::collections::HashSet;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::process;
use std::error::Error;

/// Handles a single commit by scanning its content.
///
/// # Arguments
///
/// * `repo` - A `Repository` object representing the Git repository.
/// * `commit_id` - The ID of the commit to handle, provided as a string.
/// * `scan` - A `Scan` object representing the scanning configuration.
///
/// # Returns
///
/// A `Result` containing the scanning results (`Results`) if successful,
/// otherwise an error (`Box<dyn Error>`).
pub fn handle_single_commit(repo: Repository, commit_id: &str, scan: Scan) -> Result<Results, Box<dyn Error>> {
    let commit = repo.find_commit(git2::Oid::from_str(commit_id)?)?;
    let commit_info = config_commit_info(&repo, &commit)?;
    let commits_list = vec![commit_info];

    // Handle the commit information and perform the scan
    handle_commit_info(&commits_list, scan)
}

/// Handles multiple commits by scanning their content.
///
/// # Arguments
///
/// * `repo` - A `Repository` object representing the Git repository.
/// * `commit_ids` - An array slice of commit IDs to handle, provided as strings.
/// * `scan` - A `Scan` object representing the scanning configuration.
///
/// # Returns
///
/// A `Result` containing the scanning results (`Results`) if successful,
/// otherwise an error (`Box<dyn Error>`).
pub fn handle_multiple_commits(repo: Repository, commit_ids: &[&str], scan: Scan) -> Result<Results, Box<dyn Error>> {

    let mut commits_list = vec![];

    // Iterate over each commit ID
    for commit_id in commit_ids {
        let commit = repo.find_commit(git2::Oid::from_str(commit_id)?)?;
        let commit_info = config_commit_info(&repo, &commit)?;
        commits_list.push(commit_info);
    }

    // Handle the commit information and perform the scan
    handle_commit_info(&commits_list, scan)
}

/// Handles commits from a file by scanning their content.
///
/// # Arguments
///
/// * `repo` - A `Repository` object representing the Git repository.
/// * `file_name` - The name of the file containing commit IDs, provided as a string.
/// * `scan` - A `Scan` object representing the scanning configuration.
///
/// # Returns
///
/// A `Result` containing the scanning results (`Results`) if successful,
/// otherwise an error (`Box<dyn Error>`).
pub fn handle_commits_file(repo: Repository, file_name: &str, scan: Scan) -> Result<Results, Box<dyn Error>> {
    // Open the commits file
    let file = fs::File::open(file_name).expect("Failed to open commits file");
    let reader = BufReader::new(file);

    let mut commits: Vec<String> = Vec::new();

    // Read each line from the file and store it in the commits vector
    for line in reader.lines().flatten() {
        commits.push(line);
    }

    // Convert commit IDs to a vector of string slices
    let commit_ids: Vec<&str> = commits.iter().map(|s| s.as_str()).collect();

    // Handle multiple commits using the commit IDs and perform the scan
    handle_multiple_commits(repo, &commit_ids, scan)
}

/// Handles commits within a specified time range by scanning their content.
///
/// # Arguments
///
/// * `repo` - A `Repository` object representing the Git repository.
/// * `since` - The starting time of the commit range, provided as a string.
/// * `until` - The ending time of the commit range, provided as a string.
/// * `scan` - A `Scan` object representing the scanning configuration.
///
/// # Returns
///
/// A `Result` containing the scanning results (`Results`) if successful,
/// otherwise an error (`Box<dyn Error>`).
#[allow(deprecated)]
pub fn handle_commit_range_by_time(repo: Repository, since: &str, until: &str,scan:Scan) ->Result<Results, Box<dyn Error>>{
    //TODO
    let excluded_commits: Vec<git2::Oid> = vec![];
    let is_since_rfc3339 = DateTime::parse_from_rfc3339(since).is_ok();
    let is_until_rfc3339 = DateTime::parse_from_rfc3339(until).is_ok();
    
    let is_since_date = is_valid_date_format(since);
    let is_until_date = is_valid_date_format(until);

    if is_since_date && is_until_date {
        // Convert since and until to start_time and end_time
        let start_time = match parse_date_to_datetime(since, "start") {
            Ok(datetime) => datetime.with_timezone(&FixedOffset::east(0)),
            Err(err) => {
                err.message();
                process::exit(0);
            }
        };

        let end_time = match parse_date_to_datetime(until, "until") {
            Ok(datetime) => datetime.with_timezone(&FixedOffset::east(0)),
            Err(err) => {
                err.message();
                process::exit(0);
            }
        };

         handle_multiple_commits_by_time(&repo, &excluded_commits, start_time, end_time,scan)
         
    } else if is_since_rfc3339 && is_until_rfc3339 {
        let start_time = DateTime::parse_from_rfc3339(since).unwrap();
        let end_time = DateTime::parse_from_rfc3339(until).unwrap();

        handle_multiple_commits_by_time(&repo, &excluded_commits, start_time, end_time,scan)
        
    } else {
        eprintln!("Application error: 格式不正确");
        process::exit(0);

    }
}

/// Handles multiple commits within a specified time range by scanning their content.
///
/// # Arguments
///
/// * `repo` - A reference to a `Repository` object representing the Git repository.
/// * `excluded_commits` - An array slice of excluded commit IDs, provided as `git2::Oid`.
/// * `start_time` - The starting time of the commit range, provided as `DateTime<FixedOffset>`.
/// * `end_time` - The ending time of the commit range, provided as `DateTime<FixedOffset>`.
/// * `scan` - A `Scan` object representing the scanning configuration.
///
/// # Returns
///
/// A `Result` containing the scanning results (`Results`) if successful,
/// otherwise an error (`Box<dyn Error>`).
#[allow(deprecated)]
pub fn handle_multiple_commits_by_time(
    repo: &Repository,
    excluded_commits: &[git2::Oid],
    start_time: DateTime<FixedOffset>,
    end_time: DateTime<FixedOffset>,
    scan: Scan,
) -> Result<Results, Box<dyn Error>> {
    // Get the head commit
    let head = repo.head()?;
    let obj = head.peel(git2::ObjectType::Commit)?;
    let commit = if let Some(commit) = obj.as_commit() {
        commit.clone()
    } else {
        println!("error");
        return Err(Box::new(git2::Error::from_str("Failed to convert object to commit")));
    };

    // Create a revision walker and set sorting options
    let mut revwalk = repo.revwalk()?;
    revwalk.push(commit.id())?;
    revwalk.set_sorting(git2::Sort::TOPOLOGICAL)?;

    let mut commits = Vec::new();
    let excluded_commits: HashSet<_> = excluded_commits.iter().cloned().collect();

    // Iterate over each commit ID in the revision walker
    for commit_id in revwalk {
        let oid = commit_id?;
        if excluded_commits.contains(&oid) {
            continue; // Skip excluded commits
        }

        let commit = repo.find_commit(oid)?;

        // Get the commit's time and convert it to the appropriate time zone
        let commit_time = Utc.timestamp(commit.time().seconds(), 0);
        let commit_offset = FixedOffset::west(commit.time().offset_minutes() * 60);
        let commit_date = commit_offset.from_utc_datetime(&commit_time.naive_utc());

        // Check if the commit is within the specified time range
        if commit_date >= start_time && commit_date <= end_time {
            let commit_info = config_commit_info(repo, &commit)?;
            commits.push(commit_info);
        }
    }

    // Handle the commit information and perform the scan
    handle_commit_info(&commits, scan)
}

/// Handles branches by name, scanning the commits in the matching branches.
///
/// # Arguments
///
/// * `repo` - A `Repository` object representing the Git repository.
/// * `branch_name` - The name or partial name of the branches to match.
/// * `scan` - A `Scan` object representing the scanning configuration.
///
/// # Returns
///
/// A `Result` containing the scanning results (`Results`) if successful,
/// otherwise an error (`Box<dyn Error>`).
pub fn handle_branches_by_name(
    repo: Repository,
    branch_name: &str,
    scan: Scan
) -> Result<Results, Box<dyn Error>> {
    let branches = repo.branches(Some(BranchType::Local))?;

    let mut commits = Vec::new();

    // Iterate over each branch in the repository
    for branch in branches {
        let (branch, _) = branch?;
        let branch_reference = branch.into_reference();
        let branch_name_str = branch_reference.name().unwrap_or("");

        // Check if the branch name contains the provided name or partial name
        if branch_name_str.contains(branch_name) {
            let commit_oid = branch_reference
                .target()
                .ok_or_else(|| git2::Error::from_str("Failed to get branch commit"))?;

            let commit = repo.find_commit(commit_oid)?;
            let commit_info = config_commit_info(&repo, &commit)?;

            commits.push(commit_info);
        }
    }

    // Handle the commit information and perform the scan
    handle_commit_info(&commits, scan)
}

/// Handles a commit range, scanning the commits between the specified commit IDs.
///
/// # Arguments
///
/// * `repo` - A `Repository` object representing the Git repository.
/// * `commit_from` - An optional string representing the starting commit ID.
/// * `commit_to` - An optional string representing the ending commit ID.
/// * `scan` - A `Scan` object representing the scanning configuration.
///
/// # Returns
///
/// A `Result` containing the scanning results (`Results`) if successful,
/// otherwise an error (`Box<dyn Error>`).
pub fn handle_commit_range(
    repo: Repository,
    commit_from: Option<String>,
    commit_to: Option<String>,
    scan: Scan
) -> Result<Results, Box<dyn Error>> {
    // Load all commits in the repository
    let all_commits = match load_all_commits(&repo) {
        Ok(all_commits) => all_commits,
        Err(_e) => {
            return Err(Box::new(git2::Error::from_str("Failed to convert object to commit")));
        }
    };

    // Load the commits within the specified commit range
    let results = load_commits_by_conditions(commit_from, commit_to, &all_commits);
    let commit_ids: Vec<&str> = results.iter().map(|s| s.as_str()).collect();

    // Handle multiple commits and perform the scan
    handle_multiple_commits(repo, &commit_ids, scan)
}

// NOTE: The commented-out function can be tested after specifying the repo file
// #[cfg(test)]
// mod tests {
//     use super::*;
//     static VALID_PATH: &str = "tests/TestGitOperation";
 
    
//     // Helper function to create a mock repository
//     fn create_mock_repository() -> Repository {
//         let repo = match load_repository(VALID_PATH) {
//             Ok(repo) => repo,
//             Err(e) => {
//                 eprintln!("{}", e.message());
//                 panic!("Failed to load repository");
//             }
//         };
//         repo
//     }

//     // Helper function to create a mock scan
//     fn create_mock_scan() -> Scan {
//         let rule = Rule {
//             description: String::from("Stripe Access Token"),
//             id: String::from("stripe-access-token"),
//             regex: String::from(r"(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}"),
//             entropy: Some(0.5),
//             keywords: vec![String::from("sk_test"), String::from("pk_test"),String::from("sk_live"), String::from("pk_live")],
//             allowlist: None,
//         };
//         let ruleslist:Vec<Rule>=vec![rule];

//         let keywords = vec![
//             String::from("pk_live"),
//             String::from("sk_live"),
//             String::from("sk_test"), 
//             String::from("pk_test"),];
        
//         let allowlist = Allowlist {
//         paths: vec![],
//         commits: vec![ ],
//         regex_target: String::from("match"),
//         regexes: vec![ ],
//         stopwords: vec![],
//     };

//     let scan=Scan{
//         allowlist,            
//         ruleslist,    
//         keywords
//         };
//         scan
//     }

//     // test handle_single_commit
//     #[test]
//     fn test_handle_single_commit() {
//         let repo = create_mock_repository();
//         let scan = create_mock_scan();
//         let result = handle_single_commit(repo, "8bdca802af0514ce29947e20c6be1719974ad866", scan);
//         assert!(result.is_ok());
//         match result {
//             Ok(output_items) => {
//                 assert_eq!(5, output_items.outputs[0].line_number);
//             }
//             Err(err) => {
//                 println!("Error: {}", err);
//                 assert!(false); 
//             }
//         }
//     }

//     // test handle_multiple_commits
//     #[test]
//     fn test_handle_multiple_commits() {
        
//         let repo = create_mock_repository();
//         let commit_ids = vec!["8bdca802af0514ce29947e20c6be1719974ad866", "25bc64b31ee8920e1cb1f4ea287b174df5cd9782",];
//         let scan = create_mock_scan();
//         let result = handle_multiple_commits(repo, &commit_ids, scan);
  
//         assert!(result.is_ok());
//         match result {
//             Ok(output_items) => {
//                 assert_eq!(2, output_items.commits_number);
//             }
//             Err(err) => {
//                 println!("Error: {}", err);
//                 assert!(false);
//             }
//         }
//     }

//      // test handle_commits_file
//      #[test]
//      fn test_handle_commits_file() {
   
//          let repo = create_mock_repository();
//          let file_name = "tests/files/commits.txt";
//          let scan = create_mock_scan();
 
//          // Perform the handle_commits_file function
//          let result = handle_commits_file(repo , file_name, scan);

//          assert!(result.is_ok());
//          match result {
//              Ok(output_items) => {
//                 assert_eq!(2, output_items.commits_number);
//              }
//              Err(err) => {
//                  println!("Error: {}", err);
//                  assert!(false);
//              }
//          }
//      }
     
//      // test handle_commit_range_by_time
//      #[test]
//      fn test_handle_commit_range_by_time() {
//          let repo = create_mock_repository();
//          let since = "2023-05-20T00:00:00Z";
//          let until = "2023-05-26T00:00:00Z";
//          let scan = create_mock_scan();
//          let result = handle_commit_range_by_time(repo, since, until, scan);
        
//          // Assert the result
//          assert!(result.is_ok());
//          match result {
//              Ok(output_items) => {
//                 assert_eq!(8, output_items.commits_number);
//              }
//              Err(err) => {
//                  println!("Error: {}", err);
//                  assert!(false);
//              }
//          }
//      }

//      // test test_handle_branches_by_name
//     #[test]
//     fn test_handle_branches_by_name() {
//         let repo = create_mock_repository();
//         let branch_name = "secret";
//         let scan = create_mock_scan();
//         let result = handle_branches_by_name(repo, branch_name, scan);    
//         assert!(result.is_ok());
//         match result {
//             Ok(output_items) => {
//                 assert_eq!(1, output_items.commits_number);
//             }
//             Err(err) => {
//                 println!("Error: {}", err);
//                 assert!(false);
//             }
//         }
//     }

//     // rest  handle_commit_range
//     #[test]
//     fn test_handle_commit_range() {
 
//         let repo = create_mock_repository();
//         let commit_from = Some("547b550d3ec4d1f24c12f7a4d4c8c0aaa045bd7b".to_string());
//         let commit_to = Some("42c8c6a9c48bc4d9406750f4d15b0d0cd5ab7597".to_string());
//         let scan = create_mock_scan();
//         let result = handle_commit_range(repo, commit_from, commit_to, scan);
      
//         assert!(result.is_ok());
//         match result {
//             Ok(output_items) => {
//                 assert_eq!(4, output_items.commits_number); 
//             }
//             Err(err) => {
//                 println!("Error: {}", err);
//                 assert!(false);
//             }
//         }
//     }

// }
