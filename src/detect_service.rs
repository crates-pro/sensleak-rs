use crate::*;
use chrono::Local;
use clap::Parser;
use regex::Regex;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
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
        eprintln!("Application error: {}", e);
        process::exit(0);
    }
}

/// Searches for sensitive information in a file or directory specified by the given configuration.
///
/// This function performs the detection process by scanning the specified directory for sensitive information.
/// It takes a `Config` object as input, which contains the necessary configuration parameters for the detection.
/// The function first records the start time of the scan, then loads the configuration file using the `load_config_file` function.
/// If the configuration file cannot be loaded, an error is printed, and the function exits with a non-zero status code.
/// If the specified path is a directory, the function recursively visits all files and directories within it,
/// performing the detection process for each file encountered.
/// The scan results are stored in a vector protected by a mutex to allow for concurrent access and modification.
/// Once the detection is complete, the function prints the results to the console if the `verbose` flag is set,
/// and writes the results to a report file in JSON format if a report file is specified.
/// Finally, the function prints a summary of the scan, including the number of leaks detected, the scan duration, and the current time.
///
/// # Arguments
///
/// * `config` - A `Config` object containing the configuration parameters for the detection.
///
/// # Errors
///
/// This function returns an `Err` variant if any error occurs during the detection process.
/// The error type is a boxed `dyn Error`, which allows for returning different types of error objects.
///
pub fn detect(config: Config) -> Result<(), Box<dyn Error>> {

    // Record the start time of the scan
    let start = Instant::now();
    let current_time = Local::now();
    println!("\x1b[34m[INFO]\x1b[0m[{}] Open repo ...", current_time.format("%Y-%m-%d %H:%M:%S"),);
   
    // load git repo
    let repo = match load_repository(&config.repo) {
        Ok(repo) => repo,
        Err(e) => {     
            eprintln!("{}", e.message());
            process::exit(0);
        }
    };
   
    // load allowlist, ruleslist, keywords
    let scan = match load_config_file(&config.config) {
        Ok((allowlist, ruleslist, keywords)) => Scan {
            allowlist,
            ruleslist,
            keywords,
        },
        Err(e) => {
            eprintln!("{}", e.message());
            std::process::exit(0);
        }
    };
   match (
        &config.commit,
        &config.commits,
        &config.commits_file,
        &config.commit_since,
        &config.commit_until,
        &config.commit_from,
        &config.commit_to,
        config.uncommitted,
    ) {
        (Some(commit), _, _, _, _, _, _, _) => {
           match handle_single_commit(repo, commit,scan)  {
                Ok(output_items) => {
                    config_info_after_detect(&config,output_items,start);
                },
                Err(err) => {
                    println!("Error: {}", err);
                }
            }       
            
        }
        (_, Some(commits), _, _, _, _, _, _) => {
            let commit_ids: Vec<&str> = commits.split(',').collect();
            match handle_multiple_commits(repo, &commit_ids,scan)  {
                Ok(output_items) => {
                    config_info_after_detect(&config,output_items,start);
                },
                Err(err) => {
                    println!("Error: {}", err);
                }
            }    
        }
        (_, _, Some(file_path), _, _, _, _, _) => {
            match handle_commits_file(repo, file_path,scan) {
                Ok(output_items) => {
                    config_info_after_detect(&config,output_items,start);
                },
                Err(err) => {
                    println!("Error: {}", err);
                }
            } 
        }
        (_, _, _, Some(since), Some(until), _, _, _) => {
            match handle_commit_range_by_time(repo, since, until,scan) {
                Ok(output_items) => {
                    config_info_after_detect(&config,output_items,start);
                },
                Err(err) => {
                    println!("Error: {}", err);
                }
            } 
        }
        (_, _, _, _, _, Some(commit_from), Some(commit_to), _) => {
            match handle_commit_range(repo, Some(commit_from.clone()), Some(commit_to.clone()),scan) {
                Ok(output_items) => {
                    config_info_after_detect(&config,output_items,start);
                },
                Err(err) => {
                    println!("Error: {}", err);
                }
            } 
        }
        (_, _, _, _, _, _, _, true) => {
            // TODO 
            // match handle_uncommitted_files(repo)  {
            //     Ok(output_items) => {
            //         config_info_after_detect(&config,output_items,start);
            //     },
            //     Err(err) => {
            //         println!("Error: {}", err);
            //     }
            // } 
        }
        (_, _, _, _, _, _, _, false) => {
            // TODO 
        }
    }
    Ok(())
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
    contents:&str,
    path:&str,
    ruleslist: &[Rule],
    keywords: &[String],
    allowlist: &Allowlist,
    commit_info:&CommitInfo
) -> Result<Vec<Leak>, Box<dyn Error>> {

    // global allowlist
    if is_path_in_allowlist(path, &allowlist.paths) {
        return Ok(Vec::new());
    }

    // Check if the file contents contain any keywords; if not, skip the file.
    if !is_contains_keyword(contents, keywords) {
        return Ok(Vec::new());
    }

    // println!("{}",path);
    let mut detect_info: Vec<Leak> = Vec::new(); 
    
    // Use regular expressions to find sensitive information.
    for rule in ruleslist.iter() {
        let results = detect_by_regex(path, rule, contents, allowlist);
        if results.is_empty(){
            continue;
        }
        for (line_number, line, matched) in results.iter() {
            let output_item = Leak {
                line: line.to_string(),
                line_number: *line_number as u32,
                secret: matched.to_string(),
                entropy: rule.entropy.map(|n| n.to_string()).unwrap_or_default(),
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

/// Handle the commit information by searching for secrets in the commit files.
///
/// This function takes a slice of `CommitInfo` objects, a `Scan` object, and searches for secrets in the commit files.
/// It iterates through each commit information and their associated files.
/// For each file, it calls the `detect_file` function to search for secrets using the specified rules, keywords, and allowlist.
/// If any secrets are detected in a file, the corresponding `Leak` objects are added to a vector.
/// The function returns a `Results` object containing the total number of commits and the vector of detected secrets.
///
/// # Arguments
///
/// * `commit_info_list` - A slice of `CommitInfo` objects representing the commit information.
/// * `scan` - A `Scan` object containing the rules, keywords, and allowlist for secret detection.
///
/// # Errors
///
/// This function returns an `Err` variant if any error occurs during the secret detection process.
/// The error type is a boxed `dyn Error`, which allows for returning different types of error objects.
///
pub fn handle_commit_info(commit_info_list: &[CommitInfo],scan:Scan) -> Result<Results, Box<dyn Error>> {    
    let ruleslist = scan.ruleslist;
    let keywords = scan.keywords;
    let allowlist = scan.allowlist;
    let mut results = Vec::new(); 
    for commit_info in commit_info_list {
        for (file, content) in &commit_info.files {
            let result = detect_file(content, file, &ruleslist, &keywords, &allowlist, commit_info);
            
            if let Ok(output) = result {
                if !output.is_empty() {
                    results.push(output); 
                }
            } else if let Err(err) = result {
                println!("error={}", err);
                return Err(err);
            }
        }
    }
    let flattened: Vec<Leak> = results.into_iter().flatten().collect();
    let returns= Results{
        commits_number:commit_info_list.len(),
        outputs:flattened
    };
    Ok(returns)  
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
    path:&str,
    rules: &Rule,
    contents: &'a str,
    allowlist: &Allowlist,) -> Vec<(usize, &'a str, &'a str,
 
)> {
    // Create a regular expression object.
    let regex = Regex::new(&rules.regex).unwrap();
    
    // Iterate over the lines in the string.
    let  results: Vec<(usize, &str, &str)> = contents
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
    if results.is_empty(){
        return Vec::new();
    }
    // The secrets that should be skipped
    let mut filtered_results: Vec<(usize, &str, &str)> = Vec::new();
   // Handle global allowlist
    if allowlist.regex_target == "line" {
        for (line_number, line, matched) in &results {
            if (allowlist.regexes.is_empty() ||allowlist.stopwords.is_empty()) && (is_string_matched(&allowlist.regexes, line) || is_contains_strs(&allowlist.stopwords, line)) {
                
                filtered_results.push((*line_number, line, matched));
        
            }
        }
    } else {
        for (line_number, line, matched) in &results {
            if (allowlist.regexes.is_empty() ||allowlist.stopwords.is_empty()) && ( is_string_matched(&allowlist.regexes, matched) || is_contains_strs(&allowlist.stopwords, matched)) {
          
                filtered_results.push((*line_number, line, matched));
                
            }
        }
    }

    // Handle rules.allowlist
    if let Some(rules_allowlist) = &rules.allowlist {
        // Check git commits (TODO: implement)
        // check paths
        if is_path_in_allowlist(path, &rules_allowlist.paths) {
            return vec![];
        }

        // check regexes and stopwords
        if rules_allowlist.regex_target == "line" {
            for (line_number, line, matched) in &results {
                if (rules_allowlist.regexes.is_empty() ||rules_allowlist.stopwords.is_empty()) && ( is_string_matched(&rules_allowlist.regexes, line) || is_contains_strs(&rules_allowlist.stopwords, line)) {

                    filtered_results.push((*line_number, line, matched));
                
                }
               
            }
        } else {
            for (line_number, line, matched) in &results {
                if (rules_allowlist.regexes.is_empty() ||rules_allowlist.stopwords.is_empty()) && (is_string_matched(&rules_allowlist.regexes, matched)|| is_contains_strs(&rules_allowlist.stopwords, matched)){
                    filtered_results.push((*line_number, line, matched));
                }
                
                
            }
        }
    }
    
    if filtered_results.is_empty(){
        results
    }else {
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
fn config_info_after_detect(config: &Config,results:Results,start:Instant){
        // Record the end time of the scan
        let end = Instant::now();

        // Calculate the scan duration
        let duration = end.duration_since(start);
        let current_time = Local::now();

        //  If the verbose flag is set, print the scan results to the console
        if config.verbose {
            if config.pretty {
                println!("{:#?}", results.outputs);
            } else {
                println!("{:?}", results.outputs);
            }
        }
        // If a report file is specified, write the scan results to the report file in JSON format
        if !config.report.is_empty() {
            let mut file = File::create(&config.report).expect("Failed to create file");
            let json_result = serde_json::to_string_pretty(&results.outputs[..]);
            match json_result {
                Ok(json) => {
                    // Write the JSON string to the file
                    file.write_all(json.as_bytes()).expect("Filed to wrire");
                }
                Err(e) => {
                    eprintln!("Failed to serialize JSON: {}", e);
                }
            }
        }

        println!(
            "\x1b[38;5;208m[WARN]\x1b[0m[{}]{} leaks detected. {} commits scanned in {:?}",
            current_time.format("%Y-%m-%d %H:%M:%S"),
            results.outputs.len(),
            results.commits_number,
            duration
        );

}


#[cfg(test)]
mod tests {
    use super::*;
    extern crate git2;

    use chrono::{DateTime};
    // Helper function to create a mock scan
    fn create_mock_scan() -> Scan {
        let rule = Rule {
            description: String::from("Stripe Access Token"),
            id: String::from("stripe-access-token"),
            regex: String::from(r"(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}"),
            entropy: Some(0.5),
            keywords: vec![String::from("sk_test"), String::from("pk_test"),String::from("sk_live"), String::from("pk_live")],
            allowlist: None,
        };
        let ruleslist:Vec<Rule>=vec![rule];

        let keywords = vec![
            String::from("pk_live"),
            String::from("sk_live"),
            String::from("sk_test"), 
            String::from("pk_test"),];
        
        let allowlist = Allowlist {
        paths: vec![],
        commits: vec![ ],
        regex_target: String::from("match"),
        regexes: vec![ ],
        stopwords: vec![],
    };

    let scan=Scan{
        allowlist,            
        ruleslist,    
        keywords
        };
        scan
    }

    // test detect_file
    static PATH: &str = "tests/files/testdir/test.txt";
    #[test]
    fn test_detect_file() {
       
        let scan = create_mock_scan();
        let content="twilio_api_key = SK12345678901234567890123456789012";
        let commit_info = CommitInfo {
            repo: "example/repo".to_string(),
            commit: git2::Oid::from_str("1234567890abcdef1234567890abcdef12345678").unwrap(),
            author: "John Doe".to_string(),
            email: "johndoe@example.com".to_string(),
            commit_message: "Example commit message".to_string(),
            date: DateTime::parse_from_rfc3339("2023-05-26T12:34:56+00:00").unwrap().into(),
            files: vec![
                ("/path/to/file1".to_string(), "File 1 contents".to_string()),
                ("/path/to/file2".to_string(), "File 2 contents".to_string()),
            ],
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            operation: "commit".to_string(),
        };
        // Call the detect_file function
        let result = 
        detect_file(PATH, content,&scan.ruleslist, &scan.keywords, &scan.allowlist,&commit_info);

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
            entropy: None,
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

        let result = detect_by_regex(PATH, &rules, contents, &allowlist);

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
            entropy: None,
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

        let result = detect_by_regex(PATH, &rules, contents, &allowlist);
        println!("{:?}",result);
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
            entropy: None,
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

        let result = detect_by_regex(PATH, &rules, contents, &allowlist);
        println!("{:?}",result);
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
            entropy: None,
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

        let result = detect_by_regex(PATH, &rules, contents, &allowlist);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
        assert_eq!(result[3], (7, "22", "22"));
    }
}
