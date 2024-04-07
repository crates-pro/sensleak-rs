use crate::errors::CustomError;
use crate::models::{Allowlist, CommitInfo, Config, Leak, Results, Rule, Scan};
use crate::service::git_service::*;
use crate::utils::detect_utils::{
    is_commit_in_allowlist, is_contains_strs, is_link, is_path_in_allowlist, is_string_matched,
    load_config, remove_duplicates, write_csv_report, write_json_report, write_sarif_report,
};
use crate::utils::git_util::{clone_or_load_repository, extract_repo_name};
use crate::service::db_service::insert_leaks;
use chrono::Local;
use clap::Parser;
use git2::Repository;
use rayon::ThreadPoolBuilder;
use regex::Regex;
use std::error::Error;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Starts the Git detector application.
pub async fn sensleaks() {
    let args = Config::parse();

    match detect(args).await {
        Ok(results) => results,
        Err(err) => {
            eprintln!("Application: {}", err);
            std::process::exit(0);
        }
    };
}

/// Searches for sensitive information in a repository.
///
/// # Arguments
///
/// * `config` - A `Config` struct containing the configuration settings for the detection process.
///
/// # Returns
///
/// Returns the detection results as a `Result` containing the scan results or an error.
///
pub async fn detect(config: Config) -> Result<Results, Box<dyn Error>> {
    // load repo and record the time of clone repo
    let start_clone_repo = Instant::now();
    let repo = clone_or_load_repository(&config)?;
    let duration_repo: std::time::Duration = Instant::now().duration_since(start_clone_repo);

    // load scan, which contains allowlist, ruleslist, keywords
    let mut scan = load_config(&repo, &config)?;

    // Set threads and chunk in scan
    scan.threads = config.threads;
    scan.chunk = config.chunk;

    // Record the start time of the scan
    let start_scan = Instant::now();

    // Scan
    let results = process_scan(&config, repo, scan)?;

    // To output content in the console.
    config_info_after_detect(&config, &results, start_scan, duration_repo).await?;

    Ok(results)
}

/// Processes the scan based on the provided configuration, repository, and scan settings.
///
/// # Arguments
///
/// * `config` - A reference to the `Config` object containing the scan configuration settings.
/// * `repo` - The `Repository` object representing the repository to scan.
/// * `scan` - The `Scan` object containing additional scan settings such as allowlist, ruleslist, and keywords.
///
/// # Returns
///
/// Returns the scan results as a `Result` containing the `Results` or an error.
fn process_scan(config: &Config, repo: Repository, scan: Scan) -> Result<Results, Box<dyn Error>> {
    // Scan the files that have not been submitted.
    if config.uncommitted {
        return handle_uncommitted_files(repo, &config.repo, scan);
    }

    match (
        &config.commit,
        &config.commits,
        &config.commits_file,
        &config.commit_since,
        &config.commit_until,
        &config.commit_from,
        &config.commit_to,
        &config.uncommitted,
        &config.user,
        &config.branch,
    ) {
        (Some(commit), _, _, _, _, _, _, _, Some(user), _) => {
            handle_single_commit(repo, commit, scan, user)
        }
        (_, Some(commits), _, _, _, _, _, _, Some(user), _) => {
            let commit_ids: Vec<&str> = commits.split(',').collect();
            handle_multiple_commits(repo, &commit_ids, scan, user)
        }
        (_, _, Some(file_path), _, _, _, _, _, Some(user), _) => {
            handle_commits_file(repo, file_path, scan, user)
        }
        (_, _, _, Some(since), Some(until), _, _, _, Some(user), _) => {
            handle_commit_range_by_time(repo, since, until, scan, user)
        }
        (_, _, _, _, _, Some(commit_from), Some(commit_to), _, Some(user), _) => {
            handle_commit_range(
                repo,
                Some(commit_from.clone()),
                Some(commit_to.clone()),
                scan,
                user,
            )
        }
        (_, _, _, _, _, _, _, _, Some(_user), Some(branch)) => {
            handle_branches_by_name(repo, branch, scan)
        }
        (_, _, _, _, _, _, _, _, Some(user), _) => handle_all_commits(repo, scan, user),

        _ => handle_all_commits(repo, scan, ""),
    }
}

/// Detects leaks in the provided file contents based on the specified rules and configurations.
///
///
/// The function utilizes a thread pool to execute detection operations concurrently, improving performance.
/// Detected leaks are stored in a shared mutable vector wrapped in an `Arc<Mutex>`.
///
/// # Arguments
///
/// * `contents` - The contents of the file to be scanned for leaks.
/// * `path` - The path to the file being scanned.
/// * `ruleslist` - A slice of `Rule` objects representing the rules to be applied during the detection process.
/// * `allowlist` - An `Allowlist` object containing patterns to exclude from the detection process.
/// * `commit_info` - A reference to the `CommitInfo` object containing information about the commit associated with the file.
/// * `threads` - An optional `usize` value specifying the number of threads to use in the thread pool. Default is 50.
///
/// # Returns
///
/// Returns a `Result` containing a cloned vector of `Leak` objects representing the detected leaks, or an error.
///
/// # Errors
///
/// This function can return an error if there are any issues during the detection process.
///
pub fn detect_file(
    contents: &str,
    path: &str,
    ruleslist: &[Rule],
    allowlist: &Allowlist,
    commit_info: &CommitInfo,
    threads: Option<usize>,
) -> Result<Vec<Leak>, Box<dyn Error>> {
    // Create a shared mutable vector to store detection results
    let detect_info: Arc<Mutex<Vec<Leak>>> = Arc::new(Mutex::new(Vec::new()));

    // Create a thread pool with the setting threads
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(threads.unwrap_or(50))
        .build()
        .unwrap();

    // Use the thread pool to execute the detection operations
    thread_pool.scope(|s| {
        for rule in ruleslist {
            // Check if the contents contain any keywords from the rule
            if is_contains_strs(&rule.keywords, contents) {
                let cloned_path = path.to_string();
                let cloned_rule = rule.clone();
                let cloned_contents = contents.to_string();
                let cloned_allowlist = allowlist.clone();
                let cloned_commits = commit_info.commit.to_string();
                let cloned_commit_info = commit_info.clone();
                let detect_info_clone = Arc::clone(&detect_info);

                // Spawn a thread to perform the detection using regex
                s.spawn(move |_| {
                    let results = detect_by_regex(
                        &cloned_path,
                        &cloned_rule,
                        &cloned_contents,
                        &cloned_allowlist,
                        &cloned_commits,
                    );

                    // Acquire the lock for detection results and update the vector
                    let mut detect_info = detect_info_clone.lock().unwrap();
                    for (line_number, line, matched) in results.iter() {
                        let output_item = Leak {
                            line: line.to_string(),
                            line_number: *line_number as u32,
                            offender: matched.to_string(),
                            commit: cloned_commit_info.commit.to_string(),
                            repo: cloned_commit_info.repo.to_string(),
                            rule: cloned_rule.description.to_string(),
                            commit_message: cloned_commit_info.commit_message.to_string(),
                            author: cloned_commit_info.author.to_string(),
                            email: cloned_commit_info.email.to_string(),
                            file: cloned_path.to_string(),
                            date: cloned_commit_info.date.to_string(),
                        };
                        detect_info.push(output_item);
                    }
                });
            }
        }
    });

    // Acquire the lock for detection results and return a clone of the results
    let detect_info = detect_info.lock().unwrap();
    Ok(detect_info.clone())
}

/// Searches a string for matches of a given regular expression and returns a vector of tuples.
///
/// # Arguments
///
/// * `path` - The path to the file being searched. This is used for allowlist checks.
/// * `rules` - A `Rule` object representing the rule to apply during the detection process. It contains the regular expression to match against.
/// * `contents` - A string containing the contents to search for matches.
/// * `allowlist` - An `Allowlist` object containing the allowlist configurations.
///
/// # Returns
///
/// A vector of tuples `(usize, &str, &str)`, where each tuple represents a match found in the string.
/// The first element of the tuple is the line number (1-indexed), the second element is the matched line, and the third element is the matched substring.
///
fn detect_by_regex<'a>(
    path: &str,
    rules: &Rule,
    contents: &'a str,
    allowlist: &Allowlist,
    commits: &str,
) -> Vec<(usize, &'a str, &'a str)> {
    // Create a regular expression object.
    let regex = Regex::new(&rules.regex).unwrap();

    // Iterate over the lines in the string.
    let results: Vec<(usize, &str, &str)> = contents
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            // Match the regular expression against each line.
            regex
                .captures(line)
                .and_then(|captures| captures.get(0))
                .map(|matched| (i + 1, line, matched.as_str()))
        })
        .collect();
    if results.is_empty() {
        return Vec::new();
    }

    // The secrets that should be skipped
    let mut filtered_results: Vec<(usize, &str, &str)> = Vec::new();

    // Handle global allowlist
    if allowlist.regex_target == "line" {
        for (line_number, line, matched) in &results {
            if (allowlist.regexes.is_empty() || allowlist.stopwords.is_empty())
                && (is_string_matched(&allowlist.regexes, line)
                    || is_contains_strs(&allowlist.stopwords, line))
            {
                filtered_results.push((*line_number, line, matched));
            }
        }
    } else {
        for (line_number, line, matched) in &results {
            if (allowlist.regexes.is_empty() || allowlist.stopwords.is_empty())
                && (is_string_matched(&allowlist.regexes, matched)
                    || is_contains_strs(&allowlist.stopwords, matched))
            {
                filtered_results.push((*line_number, line, matched));
            }
        }
    }

    // Handle rules.allowlist
    if let Some(rules_allowlist) = &rules.allowlist {
        // check commits and paths
        if (is_path_in_allowlist(path, &rules_allowlist.paths))
            || (is_commit_in_allowlist(commits, &rules_allowlist.commits))
        {
            return vec![];
        }

        // check regexes and stopwords
        if rules_allowlist.regex_target == "line" {
            for (line_number, line, matched) in &results {
                if (rules_allowlist.regexes.is_empty() || rules_allowlist.stopwords.is_empty())
                    && (is_string_matched(&rules_allowlist.regexes, line)
                        || is_contains_strs(&rules_allowlist.stopwords, line))
                {
                    filtered_results.push((*line_number, line, matched));
                }
            }
        } else {
            for (line_number, line, matched) in &results {
                if (rules_allowlist.regexes.is_empty() || rules_allowlist.stopwords.is_empty())
                    && (is_string_matched(&rules_allowlist.regexes, matched)
                        || is_contains_strs(&rules_allowlist.stopwords, matched))
                {
                    filtered_results.push((*line_number, line, matched));
                }
            }
        }
    }

    if filtered_results.is_empty() {
        results
    } else {
        remove_duplicates(results, filtered_results)
    }
}

/// Detects uncommitted files for sensitive information leaks.
///
/// # Arguments
///
/// * `contents` - A string slice representing the contents of the file.
/// * `path` - A string slice representing the path of the file.
/// * `ruleslist` - A reference to a slice of `Rule` objects to match against.
/// * `allowlist` - A reference to an `Allowlist` object for paths that should be skipped.
///
/// # Returns
///
/// Returns a `Result` containing a vector of `Leak` objects if sensitive information leaks are detected,
/// or an empty vector if no leaks are found.
pub fn detect_uncommitted_file(
    contents: &str,
    path: &str,
    ruleslist: &[Rule],
    allowlist: &Allowlist,
    threads: Option<usize>,
) -> Result<Vec<Leak>, Box<dyn Error>> {
    // Create a shared mutable vector to store detection results
    let detect_info: Arc<Mutex<Vec<Leak>>> = Arc::new(Mutex::new(Vec::new()));

    // Create a thread pool with the setting threads
    let thread_pool = ThreadPoolBuilder::new()
        .num_threads(threads.unwrap_or(50))
        .build()
        .unwrap();

    // Use the thread pool to execute the detection operations
    thread_pool.scope(|s| {
        for rule in ruleslist {
            // Check if the contents contain any keywords from the rule
            if is_contains_strs(&rule.keywords, contents) {
                let cloned_path = path.to_string();
                let cloned_rule = rule.clone();
                let cloned_contents = contents.to_string();
                let cloned_allowlist = allowlist.clone();
                let detect_info_clone = Arc::clone(&detect_info);

                // Spawn a thread to perform the detection using regex
                s.spawn(move |_| {
                    let results = detect_by_regex(
                        &cloned_path,
                        &cloned_rule,
                        &cloned_contents,
                        &cloned_allowlist,
                        "",
                    );

                    // Acquire the lock for detection results and update the vector
                    let mut detect_info = detect_info_clone.lock().unwrap();
                    for (line_number, line, matched) in results.iter() {
                        let output_item = Leak {
                            line: line.to_string(),
                            line_number: *line_number as u32,
                            offender: matched.to_string(),
                            commit: "".to_string(),
                            repo: "".to_string(),
                            rule: cloned_rule.description.to_string(),
                            commit_message: "".to_string(),
                            author: "".to_string(),
                            email: "".to_string(),
                            file: cloned_path.to_string(),
                            date: "".to_string(),
                        };
                        detect_info.push(output_item);
                    }
                });
            }
        }
    });

    // Acquire the lock for detection results and return a clone of the results
    let detect_info = detect_info.lock().unwrap();
    Ok(detect_info.clone())
}

/// Handles post-detection configuration information and performs actions based on the configuration settings.
///
/// # Arguments
///
/// * `config` - A reference to the `Config` object containing the scan configuration settings.
/// * `results` - A reference to the `Results` object containing the detection results.
/// * `start_scan` - The start time of the scan as an `Instant` object.
/// * `duration_repo` - The duration of the repository scanning process as a `std::time::Duration` object.
///
/// # Returns
///
/// Returns `Ok(())` if the post-detection actions are performed successfully, or an error of type `Box<dyn Error>` if any issues occur.
///
/// # Errors
///
/// This function can return an error if there are any issues during the post-detection actions, such as writing reports.
///
async fn  config_info_after_detect(
    config: &Config,
    results: &Results,
    start_scan: Instant,
    duration_repo: std::time::Duration,
) -> Result<(), Box<dyn Error>> {
    // Calculate the scan duration
    let duration_scan = Instant::now().duration_since(start_scan);

    //  If the verbose flag is set, print the scan results to the console
    if config.verbose {
        if config.pretty {
            println!("{:#?}", results.outputs);
        } else {
            println!("{:?}", results.outputs);
        }
    }

    // If the debug flag is set, print the scan results to the console
    if config.debug {
        debug_info(duration_repo, duration_scan, results.commits_number);
    }

    // Output to database
    if config.to_db {
        insert_leaks(&results.outputs).await?;
    }

    // Write output report
    match &config.report {
        Some(report) => {
            match &config.report_format {
                Some(format) => {
                    if format == "sarif" {
                        if write_sarif_report(report, &results.outputs).is_err() {
                            return Err(Box::new(CustomError::ExportSarifError));
                        }
                    } else if format == "csv" {
                        if write_csv_report(report, &results.outputs).is_err() {
                            return Err(Box::new(CustomError::ExportCsvError));
                        }
                    } else if write_json_report(report, &results.outputs).is_err() {
                        return Err(Box::new(CustomError::ExportJsonError));
                    }
                }
                None => {}
            };
        }
        None => {}
    }

    println!(
        "\x1b[38;5;208m[WARN]\x1b[0m[{}]{} leaks detected. {} commits scanned in {:?}",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        results.outputs.len(),
        results.commits_number,
        duration_scan
    );

    match &config.disk {
        Some(_disk) => {}
        None => {
            if is_link(&config.repo) {
                let dest = "workplace/";
                let mut repo_path = String::new();
                if let Some(name) = extract_repo_name(&config.repo) {
                    repo_path = format!("{}{}", dest, name);
                }
                match fs::remove_dir_all(repo_path) {
                    Ok(_) => {}
                    Err(e) => eprintln!("Delete dir fail: {}", e),
                }
            }
        }
    };
    Ok(())
}

/// Prints debug information.
///
/// # Arguments
///
/// * `total_clone_time` - The total time taken for repository cloning, represented as a `Duration` object.
/// * `total_scan_time` - The total time taken for the scan, represented as a `Duration` object.
/// * `commits` - The number of commits.
fn debug_info(
    total_clone_time: std::time::Duration,
    total_scan_time: std::time::Duration,
    commits: usize,
) {
    let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string();
    println!(
        "\x1b[34m[DEBUG]\x1b[0m[{}] -------------------------",
        timestamp
    );
    println!(
        "\x1b[34m[DEBUG]\x1b[0m[{}]  | Times and Commit Counts|",
        timestamp
    );
    println!(
        "\x1b[34m[DEBUG]\x1b[0m[{}] -------------------------",
        timestamp
    );
    println!("totalScanTime:  {:?}", total_scan_time);
    println!("totalCloneTime:  {:?}", total_clone_time);
    println!("totalCommits:  {}", commits);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate git2;

    use chrono::DateTime;
    // Helper function to create a mock scan
    fn create_mock_scan() -> Scan {
        let rule = Rule {
            description: String::from("Stripe Access Token"),
            id: String::from("stripe-access-token"),
            regex: String::from(r"(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}"),
            // entropy: Some(0.5),
            keywords: vec![
                String::from("sk_test"),
                String::from("pk_test"),
                String::from("sk_live"),
                String::from("pk_live"),
            ],
            allowlist: None,
        };
        let ruleslist: Vec<Rule> = vec![rule];

        let allowlist = Allowlist {
            paths: vec![],
            commits: vec![],
            regex_target: String::from("match"),
            regexes: vec![],
            stopwords: vec![],
        };

        let scan = Scan {
            allowlist,
            ruleslist,

            threads: Some(50),
            chunk: Some(10),
        };
        scan
    }

    // test detect_file
    static PATH: &str = "tests/files/testdir/test.txt";
    #[test]
    fn test_detect_file() {
        let scan = create_mock_scan();
        let content = "twilio_api_key = SK12345678901234567890123456789012";
        let commit_info = CommitInfo {
            repo: "example/repo".to_string(),
            commit: git2::Oid::from_str("1234567890abcdef1234567890abcdef12345678").unwrap(),
            author: "John Doe".to_string(),
            email: "johndoe@example.com".to_string(),
            commit_message: "Example commit message".to_string(),
            date: DateTime::parse_from_rfc3339("2023-05-26T12:34:56+00:00")
                .unwrap()
                .into(),
            files: vec![
                ("/path/to/file1".to_string(), "File 1 contents".to_string()),
                ("/path/to/file2".to_string(), "File 2 contents".to_string()),
            ],
        };
        // Call the detect_file function
        let result = detect_file(
            PATH,
            content,
            &scan.ruleslist,
            &scan.allowlist,
            &commit_info,
            scan.threads,
        );

        // Assert that the result is as expected
        let output = result.unwrap();
        assert_eq!(output.len(), 0);
    }
    // test detect_by_regex

    #[test]
    fn test_detect_by_regex() {
        let rules = Rule {
            description: "Digits".to_string(),
            id: "key".to_string(),
            regex: r"\d+".to_string(),
            // entropy: None,
            keywords: vec![],
            allowlist: None,
        };
        let contents = "123\n456\n789\naaaaaxwsd\ntoken=wkwk121";
        let allowlist = Allowlist {
            commits: vec![],
            paths: vec![],
            regex_target: String::new(),
            regexes: vec![],
            stopwords: vec![],
        };

        let result = detect_by_regex(PATH, &rules, contents, &allowlist, "");

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
        assert_eq!(result[3], (5, "token=wkwk121", "121"));
    }

    #[test]
    fn test_detect_by_regex_with_rules_allowlist_regex_target_match() {
        let rules = Rule {
            description: "Digits".to_string(),
            id: "key".to_string(),
            regex: r"\d+".to_string(),
            // entropy: None,
            keywords: vec![],
            allowlist: Some(Allowlist {
                commits: vec![],
                paths: vec!["tests/files/test90.txt".to_string()],
                regex_target: "match".to_string(),
                regexes: vec![],
                stopwords: vec!["token".to_string()],
            }),
        };
        let contents = "123\n456\n789\naaaaaxwsd\ntoken=wkwk121";
        let allowlist = Allowlist {
            commits: vec![],
            paths: vec![],
            regex_target: String::new(),
            regexes: vec![],
            stopwords: vec![],
        };

        let result = detect_by_regex(PATH, &rules, contents, &allowlist, "");
        println!("{:?}", result);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
        assert_eq!(result[3], (5, "token=wkwk121", "121"));
    }

    #[test]
    fn test_detect_by_regex_with_rules_allowlist_regex_target_line() {
        let rules = Rule {
            description: "Digits".to_string(),
            id: "key".to_string(),
            regex: r"\d+".to_string(),
            // entropy: None,
            keywords: vec![],
            allowlist: Some(Allowlist {
                commits: vec![],
                paths: vec!["tests/files/test90.txt".to_string()],
                regex_target: "line".to_string(),
                regexes: vec![],
                stopwords: vec!["token".to_string()],
            }),
        };
        let contents = "123\n456\n789\naaaaaxwsd\ntoken=wkwk121";
        let allowlist = Allowlist {
            commits: vec![],
            paths: vec![],
            regex_target: String::new(),
            regexes: vec![],
            stopwords: vec![],
        };

        let result = detect_by_regex(PATH, &rules, contents, &allowlist, "");
        println!("{:?}", result);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
    }

    #[test]
    fn test_detect_by_regex_with_global_allowlist() {
        let rules = Rule {
            description: "Digits".to_string(),
            id: "key".to_string(),
            regex: r"\d+".to_string(),
            // entropy: None,
            keywords: vec![],
            allowlist: Some(Allowlist {
                commits: vec![],
                paths: vec!["tests/files/test90.txt".to_string()],
                regex_target: "line".to_string(),
                regexes: vec![],
                stopwords: vec!["token".to_string()],
            }),
        };
        let contents = "123\n456\n789\naaaaaxwsd\ntoken=wkwk121\nclient22222\n22";
        let allowlist = Allowlist {
            commits: vec![],
            paths: vec![],
            regex_target: "line".to_string(),
            regexes: vec![],
            stopwords: vec!["client".to_string()],
        };

        let result = detect_by_regex(PATH, &rules, contents, &allowlist, "");
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
        assert_eq!(result[3], (7, "22", "22"));
    }
}
