use crate::*;
// use crate::errors::*;
use chrono::Local;
use clap::Parser;
use git2::Repository;
use regex::Regex;
use std::error::Error;
use std::fs;
use std::process;
use std::time::Instant;

/// Starts the Git detector application.
///
/// This function is the entry point for the Git detector application.
/// It parses the command-line arguments using the `Config::parse` function,
/// and then calls the `detect` function to start the detection process.
/// If an error occurs during the detection process, it prints the error message
/// and exits the application.
///
pub fn sensleaks() {
    let args = Config::parse();

    if let Err(e) = detect(args) {
        eprintln!("Application Error: {}", e);
        process::exit(0);
    }
}

/// Searches for sensitive information in a repository.
///
///
/// # Arguments
///
/// * `config` - A `Config` struct containing the configuration settings for the detection process.
///
/// # Errors
///
/// This function returns a `Result` that indicates whether the detection process was successful or
/// encountered an error. If an error occurs, it will be boxed as a trait object (`Box<dyn Error>`).
/// The specific error types that can be returned are not specified in the function signature.
///
pub fn detect(config: Config) -> Result<(), Box<dyn Error>> {
    // load repo
    let start_clone_repo = Instant::now();
    let repo = match clone_or_load_repository(&config) {
        Ok(repo) => repo,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(0);
        }
    };
    let duration_repo: std::time::Duration = Instant::now().duration_since(start_clone_repo);

    // load allowlist, ruleslist, keywords
    let scan_result = load_config(&repo, &config);

    // Handle the result
    let scan = match scan_result {
        Ok(scan) => scan,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            std::process::exit(0);
        }
    };

    // Record the start time of the scan
    let start_scan = Instant::now();

    // Scan
    process_scan(&config, repo, scan, start_scan, duration_repo);

    Ok(())
}

/// Processes the scan based on the provided configuration, repository, and scan settings.
///
/// # Arguments
///
/// * `config` - A reference to a `Config` struct containing the configuration settings.
/// * `repo` - A `Repository` instance representing the code repository.
/// * `scan` - A `Scan` struct containing the scan settings.
/// * `start_scan` - An `Instant` representing the start time of the scan.
/// * `duration_repo` - A `std::time::Duration` representing the duration of repository loading.
///
/// This function handles different scenarios based on the configuration settings and performs
/// the corresponding scan actions. It calls different helper functions depending on the
/// configuration parameters, processes the results, and prints information.
///
fn process_scan(
    config: &Config,
    repo: Repository,
    scan: Scan,
    start_scan: Instant,
    duration_repo: std::time::Duration,
) {
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
            match handle_single_commit(repo, commit, scan, user) {
                Ok(output_items) => {
                    config_info_after_detect(config, output_items, start_scan, duration_repo);
                }
                Err(err) => {
                    eprintln!("Error occurred: {}", err);
                }
            }
        }
        (_, Some(commits), _, _, _, _, _, _, Some(user), _) => {
            let commit_ids: Vec<&str> = commits.split(',').collect();
            match handle_multiple_commits(repo, &commit_ids, scan, user) {
                Ok(output_items) => {
                    config_info_after_detect(config, output_items, start_scan, duration_repo);
                }
                Err(err) => {
                    eprintln!("Error occurred: {}", err);
                }
            }
        }
        (_, _, Some(file_path), _, _, _, _, _, Some(user), _) => {
            match handle_commits_file(repo, file_path, scan, user) {
                Ok(output_items) => {
                    config_info_after_detect(config, output_items, start_scan, duration_repo);
                }
                Err(err) => {
                    eprintln!("Error occurred: {}", err);
                }
            }
        }
        (_, _, _, Some(since), Some(until), _, _, _, Some(user), _) => {
            match handle_commit_range_by_time(repo, since, until, scan, user) {
                Ok(output_items) => {
                    config_info_after_detect(config, output_items, start_scan, duration_repo);
                }
                Err(err) => {
                    eprintln!("Error occurred: {}", err);
                }
            }
        }
        (_, _, _, _, _, Some(commit_from), Some(commit_to), _, Some(user), _) => {
            match handle_commit_range(
                repo,
                Some(commit_from.clone()),
                Some(commit_to.clone()),
                scan,
                user,
            ) {
                Ok(output_items) => {
                    config_info_after_detect(config, output_items, start_scan, duration_repo);
                }
                Err(err) => {
                    eprintln!("Error occurred: {}", err);
                }
            }
        }
        (_, _, _, _, _, _, _, _, Some(_user), Some(branch)) => {
            match handle_branches_by_name(repo, branch, scan) {
                Ok(output_items) => {
                    config_info_after_detect(config, output_items, start_scan, duration_repo);
                }
                Err(err) => {
                    eprintln!("Error occurred: {}", err);
                }
            }
        }

        (_, _, _, _, _, _, _, Some(_uncommitted), Some(_user), _) => {
            if let Some(true) = config.uncommitted {
                match handle_uncommitted_files(repo, &config.repo, scan) {
                    Ok(output_items) => {
                        config_info_after_detect(config, output_items, start_scan, duration_repo);
                    }
                    Err(err) => {
                        eprintln!("Error occurred: {}", err);
                    }
                }
            } else {
                config_info_after_detect(config, Results::new(), start_scan, duration_repo);
            }
        }
        (_, _, _, _, _, _, _, _, Some(user), _) => match handle_all_commits(repo, scan, user) {
            Ok(output_items) => {
                config_info_after_detect(config, output_items, start_scan, duration_repo);
            }
            Err(err) => {
                eprintln!("Error occurred: {}", err);
            }
        },

        _ => match handle_all_commits(repo, scan, "") {
            Ok(output_items) => {
                config_info_after_detect(config, output_items, start_scan, duration_repo);
            }
            Err(err) => {
                eprintln!("Error occurred: {}", err);
            }
        },
    }
}

/// Search a file for secrets using a set of regular expressions.
///
/// This function reads the contents of the specified file and searches for secrets using a set of regular expressions.
/// It takes the file path, a slice of `Rule` objects, a slice of keywords, and an `Allowlist` object as input.
/// If the file contents do not contain any of the specified keywords, the function returns an empty vector, indicating no secrets were found.
/// Otherwise, it iterates through the ruleslist and uses regular expressions to find matches in the file contents.
/// For each match, an `Leak` is created and added to a vector.
/// The function returns the vector of `Leak`s, representing the detected secrets.
///
/// # Arguments
///
/// * `contents` - The contents of the file to search for secrets.
/// * `path` - The path to the file being searched.
/// * `ruleslist` - A slice of `Rule` objects representing the set of rules to apply during the detection process.
/// * `keywords` - A slice of strings representing the keywords to search for in the file contents.
/// * `allowlist` - An `Allowlist` object containing the paths to ignore during the detection process.
/// * `commit_info` - A `CommitInfo` object representing the information about the commit.
///
/// # Errors
///
/// This function returns an `Err` variant if any error occurs during the file reading process.
/// The error type is a boxed `dyn Error`, which allows for returning different types of error objects.
pub fn detect_file(
    contents: &str,
    path: &str,
    ruleslist: &[Rule],
    keywords: &[String],
    allowlist: &Allowlist,
    commit_info: &CommitInfo,
) -> Result<Vec<Leak>, Box<dyn Error>> {
    // check paths in global allowlist
    if (is_path_in_allowlist(path, &allowlist.paths))
        || (is_commit_in_allowlist(commit_info.commit.to_string().as_str(), &allowlist.commits))
    {
        return Ok(Vec::new());
    }

    // Check if the file contents contain any keywords; if not, skip the file.
    if !is_contains_keyword(contents, keywords) {
        return Ok(Vec::new());
    }

    // Use regular expressions to find sensitive information.
    let mut detect_info: Vec<Leak> = Vec::new();
    for rule in ruleslist.iter() {
        let results = detect_by_regex(
            path,
            rule,
            contents,
            allowlist,
            commit_info.commit.to_string().as_str(),
        );
        if results.is_empty() {
            continue;
        }
        for (line_number, line, matched) in results.iter() {
            let output_item = Leak {
                line: line.to_string(),
                line_number: *line_number as u32,
                offender: matched.to_string(),

                commit: commit_info.commit.to_string(),
                repo: commit_info.repo.to_string(),
                rule: rule.description.to_string(),
                commit_message: commit_info.commit_message.to_string(),
                author: commit_info.author.to_string(),
                email: commit_info.email.to_string(),
                file: path.to_string(),
                date: commit_info.date.to_string(),
                tags: "".to_string(),
                operation: commit_info.operation.to_string(),
            };
            detect_info.push(output_item);
        }
    }
    Ok(detect_info)
}

/// Detects uncommitted files for sensitive information leaks.
///
/// This function takes the `contents` of a file, its `path`, a list of `ruleslist` to match against,
/// a list of `keywords` to check for, and an `allowlist` for paths that should be skipped.
///
/// It returns a `Result` containing a vector of `Leak` objects if successful, or an `Err` variant
/// of the custom `LeakError` type if an error occurs.
///
/// # Arguments
///
/// * `contents` - A string slice representing the contents of the file.
/// * `path` - A string slice representing the path of the file.
/// * `ruleslist` - A reference to a slice of `Rule` objects to match against.
/// * `keywords` - A reference to a slice of strings representing keywords to check for.
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
    keywords: &[String],
    allowlist: &Allowlist,
) -> Result<Vec<Leak>, Box<dyn Error>> {
    // check paths in global allowlist
    if is_path_in_allowlist(path, &allowlist.paths) {
        return Ok(Vec::new());
    }

    // Check if the file contents contain any keywords; if not, skip the file.
    if !is_contains_keyword(contents, keywords) {
        return Ok(Vec::new());
    }

    // Use regular expressions to find sensitive information.
    let mut detect_info: Vec<Leak> = Vec::new();
    for rule in ruleslist.iter() {
        let results = detect_by_regex(path, rule, contents, allowlist, "");
        if results.is_empty() {
            continue;
        }
        for (line_number, line, matched) in results.iter() {
            let output_item = Leak {
                line: line.to_string(),
                line_number: *line_number as u32,
                offender: matched.to_string(),

                commit: "".to_string(),
                repo: "".to_string(),
                rule: rule.description.to_string(),
                commit_message: "".to_string(),
                author: "".to_string(),
                email: "".to_string(),
                file: path.to_string(),
                date: "".to_string(),
                tags: "".to_string(),
                operation: "".to_string(),
            };
            detect_info.push(output_item);
        }
    }
    Ok(detect_info)
}

/// Searches a string for matches of a given regular expression and returns a vector of tuples.
///
/// This function takes a `Path` object, a `Rule` object, a string containing the contents to search, and an `Allowlist` object as input.
/// It uses the provided regular expression to search for matches within the contents string.
/// The function returns a vector of tuples, where each tuple contains the line number, the line itself, and the matched substring.
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

/// Configures and displays scan information after the detection process.
///
/// # Arguments
///
/// * `config` - A reference to a `Config` object representing the scan configuration.
/// * `results` - The scanning results (`Results`) to be displayed.
/// * `start` - The starting time of the scan (`Instant`).
///
fn config_info_after_detect(
    config: &Config,
    results: Results,
    start_scan: Instant,
    duration_repo: std::time::Duration,
) {
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

    // Write output report
    if !config.report.is_empty() {
        match config.report_format.as_str() {
            "json" => {
                if let Err(e) = write_json_report(&config.report, &results.outputs) {
                    eprintln!("Error occurred: {}", e);
                }
            }
            "sarif" => {
                if let Err(e) = write_sarif_report(&config.report, &results.outputs) {
                    eprintln!("Error occurred: {}", e);
                }
            }
            "csv" => {
                if let Err(e) = write_csv_report(&config.report, &results.outputs) {
                    eprintln!("Error occurred: {}", e);
                }
            }
            _ => {
                eprintln!("Error occurred: Invalid report format {}", config.report_format);
            }
        }
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
}

/// Prints debug information.
///
/// # Arguments
///
/// * `total_clone_time` - The total time taken for repository cloning, represented as a `Duration` object.
/// * `total_scan_time` - The total time taken for the scan, represented as a `Duration` object.
/// * `commits` - The number of commits.
pub fn debug_info(
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

/// Loads the scan configuration from either the target repository or a configuration file.
///
/// # Arguments
///
/// * `repo` - A `Repository` object representing the repository.
/// * `config` - A `Config` object containing the configuration settings.
///
/// # Returns
///
/// Returns a `Scan` object containing the allowlist, ruleslist, and keywords for the scan.
///
/// # Panics
///
/// This function may panic if any of the following conditions occur:
///
/// * The target repository config file is empty.
/// * An error occurs while loading the config file.
fn load_config(repo: &Repository, config: &Config) -> Result<Scan, Box<dyn Error>> {
    let scan_result = if config.repo_config {
        match load_config_content_from_target_repo(repo) {
            Ok(Some(content)) => load_config_from_target_repo(&content),
            Ok(None) => {
                eprintln!("Error occurred: Empty config file!");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error occurred: {}", e);
                std::process::exit(0);
            }
        }
    } else {
        load_config_file(&config.config)
    };

    match scan_result {
        Ok(scan) => Ok(scan),
        Err(e) => {
            eprintln!("Error occurred: {}", e);
            std::process::exit(0);
        }
    }
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

        let keywords = vec![
            String::from("pk_live"),
            String::from("sk_live"),
            String::from("sk_test"),
            String::from("pk_test"),
        ];

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
            keywords,
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
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            operation: "commit".to_string(),
        };
        // Call the detect_file function
        let result = detect_file(
            PATH,
            content,
            &scan.ruleslist,
            &scan.keywords,
            &scan.allowlist,
            &commit_info,
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
