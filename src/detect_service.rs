use crate::*;
use chrono::Local;
use clap::Parser;
use rayon::prelude::*;
use regex::Regex;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Instant;



/// Starts the Git detector application.
///
/// This function is the entry point for the Git detector application.
/// It parses the command-line arguments using the `Config::parse` function,
/// and then calls the `detect` function to start the detection process.
/// If an error occurs during the detection process, it prints the error message
/// and exits the application.
///
pub fn git_detector() {
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

    // Get the path of the repository to scan
    let path = Path::new(&config.repo);

    // Create a mutex-protected vector to store the scan results
    let results_mutex = Arc::new(Mutex::new(Vec::new()));

    // load configs
    let (allowlist, ruleslist, keywords) = match load_config_file(&config.config, &config.repo) {
        Ok((allowlist, ruleslist, keywords)) => (allowlist, ruleslist, keywords),
        Err(e) => {
            eprintln!("Error: {}", e.message());
            std::process::exit(1);
        }
    };

    // Start to detect
    if path.is_dir() {
        visit_dirs(
            path,
            &config,
            &allowlist,
            &ruleslist,
            &keywords,
            results_mutex.clone(),
        )?;
        let results = results_mutex.lock().unwrap();

        // Record the end time of the scan
        let end = Instant::now();

        // Calculate the scan duration
        let duration = end.duration_since(start);
        let current_time = Local::now();

        //  If the verbose flag is set, print the scan results to the console
        if config.verbose {
            if config.pretty {
                println!("{:#?}", results);
            } else {
                println!("{:?}", results);
            }
        }
        // If a report file is specified, write the scan results to the report file in JSON format
        if !config.report.is_empty() {
            let mut file = File::create(config.report).expect("Failed to create file");
            let json_result = serde_json::to_string_pretty(&results[..]);
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
            "\x1b[38;5;208mWARN:\x1b[0m[{}]{} leaks detected. XXX commits scanned in {:?}",
            current_time.format("%Y-%m-%d %H:%M:%S"),
            results.len(),
            duration
        );
    } else {
        eprintln!("{} is not a valid directory", path.display());
    }
    Ok(())
}

/// Recursively searches for files and directories within the specified directory, ignoring any files or directories in the allowlist_paths.
///
/// This function is used to recursively visit all files and directories within a given directory.
/// It skips hidden files and files in the allowlist_paths specified in the `Allowlist` configuration.
/// For each file encountered, it performs the detection process using the `detect_file` function,
/// and stores the results in a vector protected by a mutex to allow for concurrent access and modification.
/// If a subdirectory is encountered, the function recursively calls itself to visit the subdirectory.
///
/// # Arguments
///
/// * `dir` - The path to the directory to visit.
/// * `config` - A reference to the `Config` object containing the configuration parameters.
/// * `allowlist` - A reference to the `Allowlist` object containing the paths to ignore during the detection process.
/// * `ruleslist` - A slice of `Rule` objects containing the rules to apply during the detection process.
/// * `keywords` - A slice of strings representing the keywords to search for during the detection process.
/// * `results_mutex` - An `Arc<Mutex<Vec<OutputItem>>>` object that provides thread-safe access to the results vector.
///
/// # Errors
///
/// This function returns an `Err` variant if any error occurs during the recursive visitation process.
/// The error type is a boxed `dyn Error`, which allows for returning different types of error objects.
///
fn visit_dirs(
    dir: &Path,
    _config: &Config,
    allowlist: &Allowlist,
    ruleslist: &[Rule],
    keywords: &[String],
    results_mutex: Arc<Mutex<Vec<OutputItem>>>,
) -> Result<(), Box<dyn Error>> {
    if dir.is_dir() {
        let entries: Vec<_> = fs::read_dir(dir)?.collect();
        entries.par_iter().for_each(|entry| {
            if let Ok(entry) = entry {
                let path = entry.path();
                // Skip hidden files.
                if let Some(filename) = entry.file_name().to_str() {
                    if filename.starts_with('.') || filename.contains('~')  {
                        return;
                    }
                }
                // Skip files in allowlist_paths.
                // Recursively searches all files in a given directory and its subdirectories for matches.
                // Saves the search results for each scanned file.
                if path.is_dir() {
                    if !is_path_in_allowlist(&path, &allowlist.paths) {

                        visit_dirs(
                            &path,
                            _config,
                            allowlist,
                            ruleslist,
                            keywords,
                            results_mutex.clone(),
                        )
                        .unwrap();
                    }
                } else if path.is_file() && !is_path_in_allowlist(&path, &allowlist.paths){
        
                    let result = detect_file(&path, ruleslist, keywords, allowlist).unwrap();
                    let mut results = results_mutex.lock().unwrap();
                    results.extend(result);
                   
                }
            }
        });
    }
    Ok(())
}

/// Search a file for secrets using a set of regular expressions.
///
/// This function reads the contents of the specified file and searches for secrets using a set of regular expressions.
/// It takes the file path, a slice of `Rule` objects, a slice of keywords, and an `Allowlist` object as input.
/// If the file contents do not contain any of the specified keywords, the function returns an empty vector, indicating no secrets were found.
/// Otherwise, it iterates through the ruleslist and uses regular expressions to find matches in the file contents.
/// For each match, an `OutputItem` is created and added to a vector.
/// The function returns the vector of `OutputItem`s, representing the detected secrets.
///
/// # Arguments
///
/// * `path` - The path to the file to search for secrets.
/// * `ruleslist` - A slice of `Rule` objects representing the set of rules to apply during the detection process.
/// * `keywords` - A slice of strings representing the keywords to search for in the file contents.
/// * `allowlist` - An `Allowlist` object containing the paths to ignore during the detection process.
///
/// # Errors
///
/// This function returns an `Err` variant if any error occurs during the file reading process.
/// The error type is a boxed `dyn Error`, which allows for returning different types of error objects.
fn detect_file(
    path: &Path,
    ruleslist: &[Rule],
    keywords: &[String],
    allowlist: &Allowlist,
) -> Result<Vec<OutputItem>, Box<dyn Error>> {
    // Get the contents of the file.
    let contents = fs::read_to_string(path)?;

    // Check if the file contents contain any keywords; if not, skip the file.
    if !is_contains_keyword(&contents, keywords) {
        return Ok(Vec::new());
    }

    let mut detect_info: Vec<OutputItem> = Vec::new(); 
    
    // Use regular expressions to find sensitive information.
    for rule in ruleslist.iter() {
        
        let results = detect_by_regex(path, rule, &contents, allowlist);
        for (line_number, line, matched) in results.iter() {
            let output_item = OutputItem {
                line: line.to_string(),
                line_number: *line_number as u32,
                secret: matched.to_string(),
                entropy: rule.entropy.map(|n| n.to_string()).unwrap_or_default(),
                commit: "".to_string(),
                repo: "".to_string(),
                rule: rule.description.to_string(),
                commit_message: "".to_string(),
                author: "".to_string(),
                email: "".to_string(),
                file: path.to_string_lossy().to_string(),
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
    path: &Path,
    rules: &Rule,
    contents: &'a str,
    allowlist: &Allowlist,
) -> Vec<(usize, &'a str, &'a str)> {
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
    remove_duplicates(results, filtered_results)
}



#[cfg(test)]
mod tests {
    use super::*;

    // test detect
    #[test]
    fn test_git_detector() {
        let config = Config {
            repo: "tests/files/testDir".to_string(),
            config: "gitleaks.toml".to_string(),
            report: "".to_string(),
            verbose: false,
            pretty: false,
        };
        
        let result = detect(config);
        assert!(result.is_ok()); 
    }

    // test visit_dirs
    #[test]
    fn test_visit_dirs() {
        let config = Config {
            repo: "tests/files/testDir".to_string(),
            config: "gitleaks.toml".to_string(),
            report: "".to_string(),
            verbose: true,
            pretty: false,
        };
        let allowlist = Allowlist {
            commits: vec![],
            paths: vec![],
            regex_target: String::new(),
            regexes: vec![],
            stopwords: vec![],
        };
        let ruleslist = vec![ Rule {
            description: "Digits".to_string(),
            id: "key".to_string(),
            regex: r"\d+".to_string(),
            entropy: None,
            keywords: vec![],
            allowlist: None,
        }];
        let keywords = vec!["keyword1".to_string(), "keyword2".to_string()];
        let results_mutex = Arc::new(Mutex::new(Vec::new()));

        let result = visit_dirs(
            Path::new(&config.repo),
            &config,
            &allowlist,
            &ruleslist,
            &keywords,
            results_mutex.clone(),
        );

        assert!(result.is_ok());  

    }
    
    // test detect_file
    
    #[test]
    fn test_detect_file() {
        // Create a temporary file with test data
        let path = Path::new("tests/files/testDir/test.txt");
        // Define test data
        let rule = Rule::new();

        let ruleslist = vec![rule];
        let keywords = vec!["test".to_string()];
        let allowlist = Allowlist::new();

        // Call the detect_file function
        let result = detect_file(&path, &ruleslist, &keywords, &allowlist);

        // Assert that the result is as expected
        let output = result.unwrap();
        assert_eq!(output.len(), 0);
    }
    // test detect_by_regex
    #[test]
    fn test_detect_by_regex() {
        let path = Path::new("tests/files/testdir/test.txt");
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

        let result = detect_by_regex(&path, &rules, contents, &allowlist);

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
        assert_eq!(result[3], (5, "token=wkwk121", "121"));
    }
   
    #[test]
    fn test_detect_by_regex_with_rules_allowlist_regex_target_match() {
        let path = Path::new("tests/files/testdir/test.txt");
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

        let result = detect_by_regex(&path, &rules, contents, &allowlist);
        println!("{:?}",result);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
        assert_eq!(result[3], (5, "token=wkwk121", "121"));
    }

    #[test]
    fn test_detect_by_regex_with_rules_allowlist_regex_target_line() {
        let path = Path::new("tests/files/testdir/test.txt");
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

        let result = detect_by_regex(&path, &rules, contents, &allowlist);
        println!("{:?}",result);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));

    }
   
    #[test]
    fn test_detect_by_regex_with_global_allowlist() {
        let path = Path::new("tests/files/testdir/test.txt");
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

        let result = detect_by_regex(&path, &rules, contents, &allowlist);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], (1, "123", "123"));
        assert_eq!(result[1], (2, "456", "456"));
        assert_eq!(result[2], (3, "789", "789"));
        assert_eq!(result[3], (7, "22", "22"));
    }
}
