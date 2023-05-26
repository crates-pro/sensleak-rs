use crate::errors::CustomError;
use crate::models::{Allowlist, Config, CsvResult, Leak, Rule, Scan};
use csv::Writer;
use git2::Repository;
use regex::Regex;
use serde_json::json;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use toml::{to_string_pretty, Value};

/// Loads the scan configuration based on the specified repository and configuration settings.
///
/// # Arguments
///
/// * `repo` - A reference to the `Repository` object representing the target repository.
/// * `config` - A reference to the `Config` object containing the scan configuration settings.
///
/// # Returns
///
/// Returns a `Result` containing the loaded `Scan` object if successful, or an error of type `Box<dyn Error>` if any issues occur.
///
pub fn load_config(repo: &Repository, config: &Config) -> Result<Scan, Box<dyn Error>> {
    let scan_result = if config.repo_config {
        // Load config from target repo. Config file must be ".gitleaks.toml" or "gitleaks.toml"
        let content = load_config_content_from_target_repo(repo)?;
        match content {
            Some(content) => load_config_from_target_repo(&content),
            None => {
                return Err(Box::new(CustomError::EmptyFileError));
            }
        }
    } else {
        // Specify the search rule file.
        load_config_file(&config.config)
    }?;

    Ok(scan_result)
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
fn load_config_content_from_target_repo(
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

/// Loads the configuration file and extracts the allowlist, ruleslist.
///
/// # Arguments
///
/// * `config_file_path` - The path to the configuration file.
/// * `repo_file_path` - The path of the repository file.
///
/// # Returns
///
/// Returns an `Ok` variant containing a tuple with the extracted allowlist, ruleslist, and keywords.
///
/// # Errors
///
/// Returns an `Err` variant if the configuration file cannot be loaded or if there are any errors during parsing.
///
pub fn load_config_file(config_file_path: &str) -> Result<Scan, Box<dyn Error>> {
    // Load config file
    let toml_str = fs::read_to_string(config_file_path)
        .map_err(|_| Box::new(CustomError::EmptyConfigFileError))?;

    // Parse config file
    let config_file_content: Value = toml::from_str(&toml_str)?;

    // Config allowlist
    let allowlist = config_allowlist(&config_file_content)?;

    // Config ruleslist and keywords
    let ruleslist= config_ruleslist_and_keywords(&config_file_content)?;

    let scan = Scan {
        allowlist,
        ruleslist,
        threads: None,
        chunk: None,
    };

    Ok(scan)
}

/// Loads the configuration from the target repository.
///
/// # Arguments
///
/// * `toml_str` - A TOML string representing the configuration file from the target repository.
///
/// # Returns
///
/// Returns an `Ok` variant containing a tuple with the extracted allowlist, ruleslist, and keywords.
///
/// # Errors
///
/// Returns an `Err` variant if there are any errors during parsing or extraction.
///
fn load_config_from_target_repo(toml_str: &str) -> Result<Scan, Box<dyn Error>> {
    // Load config file
    let config_file_content: Value = toml::from_str(toml_str)?;

    // Config allowlist
    let allowlist = config_allowlist(&config_file_content)?;

    // Config ruleslist and keywords
    let ruleslist= config_ruleslist_and_keywords(&config_file_content)?;

    let scan = Scan {
        allowlist,
        ruleslist,
        threads: None,
        chunk: None,
    };

    Ok(scan)
}

/// Extracts the allowlist from the config file.
///
/// # Arguments
///
/// * `config_file_content` - The TOML content of the configuration file.
/// * `repo_file_path` - The path of the repository file.
///
/// # Returns
///
/// Returns an `Ok` variant containing the extracted `Allowlist` object.
///
fn config_allowlist(config_file_content: &Value) -> Result<Allowlist, Box<dyn Error>> {
    let mut allowlist = Allowlist {
        paths: Vec::new(),
        commits: Vec::new(),
        regex_target: String::from(""),
        regexes: Vec::new(),
        stopwords: Vec::new(),
    };

    // Get paths
    if let Some(file_list) = config_file_content
        .get("allowlist")
        .and_then(|v| v.get("paths").and_then(|v| v.as_array()))
    {
        for path in file_list.iter() {
            let path_str = path
                .as_str()
                .ok_or_else(|| Box::<dyn Error>::from(CustomError::InvalidTomlFile))?
                .to_string();
            allowlist.paths.push(path_str);
        }
    }

    // Get commit
    if let Some(regex_list) = config_file_content
        .get("allowlist")
        .and_then(|v| v.get("commits").and_then(|v| v.as_array()))
    {
        allowlist.commits = regex_list
            .iter()
            .filter_map(|r| r.as_str())
            .map(|s| s.to_string())
            .collect();
    }

    // Get regex target (default to "match")
    if let Some(target) = config_file_content
        .get("allowlist")
        .and_then(|v| v.get("regexTarget").and_then(|v| v.as_str()))
    {
        allowlist.regex_target = target.to_string();
    }

    // Get regexes
    if let Some(regex_list) = config_file_content
        .get("allowlist")
        .and_then(|v| v.get("regexes").and_then(|v| v.as_array()))
    {
        allowlist.regexes = regex_list
            .iter()
            .filter_map(|r| r.as_str())
            .map(|s| s.to_string())
            .collect();
    }

    // Get stopwords
    if let Some(stopwords_list) = config_file_content
        .get("allowlist")
        .and_then(|v| v.get("stopwords").and_then(|v| v.as_array()))
    {
        allowlist.stopwords = stopwords_list
            .iter()
            .filter_map(|r| r.as_str())
            .map(|s| s.to_string())
            .collect();
    }

    Ok(allowlist)
}

/// Extracts the rules list and keywords from the config file.
///
/// # Arguments
///
/// * `config_file_content` - The TOML content of the configuration file.
/// * `repo_file_path` - The path of the repository file.
///
/// # Returns
///
/// Returns a tuple containing the extracted `ruleslist` and `keywords`.
/// * `ruleslist` - A vector of `Rule` objects representing the rules for detection.
/// * `keywords` - A vector of strings representing the keywords used for detection.
///
fn config_ruleslist_and_keywords(
    config_file_content: &Value,
) -> Result<Vec<Rule>, Box<dyn Error>> {
    let mut ruleslist = vec![];

    let regex_array = config_file_content
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Box::<dyn Error>::from(CustomError::InvalidTomlFile))?;

    for rule in regex_array {
        let description = rule
            .get("description")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| Box::<dyn Error>::from(CustomError::InvalidTomlFile))?;
        let id = rule
            .get("id")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| Box::<dyn Error>::from(CustomError::InvalidTomlFile))?;
        let regex = rule
            .get("regex")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| Box::<dyn Error>::from(CustomError::InvalidTomlFile))?;
        // let entropy: Option<f64> = rule.get("entropy").map(|e| e.as_float().unwrap());
        let keywords_array = rule
            .get("keywords")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Box::<dyn Error>::from(CustomError::InvalidTomlFile))?;

        let mut rules_allowlist = Allowlist {
            commits: vec![],
            paths: vec![],
            regex_target: String::new(),
            regexes: vec![],
            stopwords: vec![],
        };

        if rule.get("allowlist").is_none() {
            let rule = Rule {
                description,
                id,
                regex,
                keywords: keywords_array
                    .iter()
                    .map(|kw| kw.as_str().unwrap().to_string())
                    .collect(),
                allowlist: None,
            };
            ruleslist.push(rule);
            continue;
        }

        if let Some(allowlist_table) = rule.get("allowlist") {
            if let Some(commits_array) = allowlist_table.get("commits").and_then(|v| v.as_array()) {
                for commit in commits_array {
                    if let Some(commit_str) = commit.as_str() {
                        rules_allowlist.commits.push(commit_str.to_string());
                    }
                }
            }

            if let Some(paths_array) = allowlist_table.get("paths").and_then(|v| v.as_array()) {
                for path in paths_array {
                    if let Some(path_str) = path.as_str() {
                        rules_allowlist.paths.push(path_str.to_string());
                    }
                }
            }

            rules_allowlist.regex_target = allowlist_table
                .get("regexTarget")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(regexes_array) = allowlist_table.get("regexes").and_then(|v| v.as_array()) {
                for regex in regexes_array {
                    if let Some(regex_str) = regex.as_str() {
                        rules_allowlist.regexes.push(regex_str.to_string());
                    }
                }
            }

            if let Some(stopwords_array) =
                allowlist_table.get("stopwords").and_then(|v| v.as_array())
            {
                for stopword in stopwords_array {
                    if let Some(stopword_str) = stopword.as_str() {
                        rules_allowlist.stopwords.push(stopword_str.to_string());
                    }
                }
            }
        }

        let rule = Rule {
            description,
            id,
            regex,
            keywords: keywords_array
                .iter()
                .map(|kw| kw.as_str().unwrap().to_string())
                .collect(),
            allowlist: Some(rules_allowlist),
        };
        ruleslist.push(rule);
    }

    Ok(ruleslist)
}

/// Appends a rule to a TOML file.
///
/// # Arguments
///
/// * `rule` - A reference to the `Rule` object to be appended to the TOML file.
/// * `filename` - The name of the TOML file to which the rule should be appended.
///
/// # Returns
///
/// Returns `Ok(())` if the rule is successfully appended to the TOML file, or an error of type `Box<dyn Error>`
/// if any issues occur.
///
/// # Errors
///
/// This function can return an error if there are any issues during the file operations, such as opening the file,
/// moving the file pointer, or writing the rule contents.
///
pub fn append_rule_to_toml(rule: &Rule, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Open the file with read, write, and append options
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .open(filename)?;

    // Move the file pointer to the end of the file
    file.seek(SeekFrom::End(0))?;

    // Write the start marker for a new [[rules]] section
    file.write_all(b"[[rules]]\n")?;

    // Serialize the Rule struct to a TOML string
    let toml_string = toml::to_string(rule)?;

    // Write the contents of the Rule
    file.write_all(toml_string.as_bytes())?;

    // Write a newline character to separate different [[rules]]
    file.write_all(b"\n")?;

    Ok(())
}

/// Deletes a rule with the specified ID from a TOML file.
///
/// # Arguments
///
/// * `file_path` - A string slice representing the path to the TOML file.
/// * `rule_id` - A string slice representing the ID of the rule to be deleted.
///
/// # Returns
///
/// Returns `Ok(())` if the rule with the specified ID is successfully deleted from the TOML file, or an error of
/// type `Box<dyn Error>` if any issues occur.
///
/// # Errors
///
/// This function can return an error if there are any issues during the file operations, such as reading the file,
/// parsing the TOML content, modifying the data, or writing the modified TOML to the file.
///
pub fn delete_rule_by_id(file_path: &str, rule_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Read the content of the TOML file
    let toml_content = fs::read_to_string(file_path)?;

    // Parse the TOML content
    let mut toml_data: Value = toml::from_str(&toml_content)?;

    // Delete rules with the specified id
    if let Some(rules) = toml_data.get_mut("rules") {
        if let Some(rules_array) = rules.as_array_mut() {
            rules_array.retain(|rule| {
                if let Some(id) = rule.get("id") {
                    // Delete the rule based on the id
                    let rule_id_value = id.as_str().unwrap();
                    rule_id_value != rule_id
                } else {
                    true
                }
            });
        }
    }

    // Convert the modified TOML data back to a string
    let modified_toml = to_string_pretty(&toml_data)?;

    // Write the modified TOML to the file
    fs::write(file_path, modified_toml)?;

    Ok(())
}


/// Updates a rule with the specified ID in a TOML file.
///
/// # Arguments
///
/// * `file_path` - A string slice representing the path to the TOML file.
/// * `rule_id` - A string slice representing the ID of the rule to be updated.
/// * `new_rule` - A reference to the updated `Rule` object.
///
/// # Returns
///
/// Returns `Ok(())` if the rule with the specified ID is successfully updated in the TOML file, or an error of
/// type `Box<dyn Error>` if any issues occur.
///
pub fn update_rule_by_id(file_path: &str, rule_id: &str, new_rule: &Rule) -> Result<(), Box<dyn Error>> {
    
    let toml_content = fs::read_to_string(file_path)?;
 
    let mut toml_data: toml::Value = toml::from_str(&toml_content)?;

    // Update rules with the specified ID
    if let Some(rules) = toml_data.get_mut("rules") {
        if let Some(rules_array) = rules.as_array_mut() {
            for rule in rules_array.iter_mut() {
                if let Some(id) = rule.get("id") {
                    let rule_id_value = id.as_str().unwrap();
                    if rule_id_value == rule_id {
                        // Update the rule with the new values
                        *rule = toml::value::Value::try_from(new_rule)?;
                        break;
                    }
                }
            }
        }
    }

 
    let modified_toml = toml::to_string_pretty(&toml_data)?;

 
    fs::write(file_path, modified_toml)?;

    Ok(())
}
 



/// Writes a JSON report with the provided `Leak` results to the specified file path.
///
/// # Arguments
///
/// * `file_path` - The file path where the JSON report will be written.
/// * `results` - A slice containing the `Leak` results to be included in the report.
///
/// # Returns
///
/// * `Result<(), Box<dyn Error>>` - Returns `Ok(())` if the JSON report is written successfully,
///   or an `Err` variant containing the error information.
///
pub fn write_json_report(file_path: &str, results: &[Leak]) -> Result<(), Box<dyn Error>> {
    let json_result = serde_json::to_string_pretty(results)?;
    let mut file = File::create(file_path)?;
    file.write_all(json_result.as_bytes())?;
    Ok(())
}

/// Writes a SARIF report with the provided `Leak` results to the specified file path.
///
/// # Arguments
///
/// * `file_path` - The file path where the SARIF report will be written.
/// * `results` - A slice containing the `Leak` results to be included in the report.
///
/// # Returns
///
/// * `Result<(), Box<dyn Error>>` - Returns `Ok(())` if the SARIF report is written successfully,
///   or an `Err` variant containing the error information.
///
pub fn write_sarif_report(file_path: &str, results: &[Leak]) -> Result<(), Box<dyn Error>> {
    let sarif_result = convert_to_sarif(results)?;
    let mut file = File::create(file_path)?;
    file.write_all(sarif_result.as_bytes())?;
    Ok(())
}

/// Converts the provided `Leak` results into a SARIF JSON string.
///
/// # Arguments
///
/// * `results` - A slice containing the `Leak` results to be converted.
///
/// # Returns
///
/// * `Result<String, Error>` - Returns a `String` containing the SARIF JSON if the conversion is
///   successful, or an `Error` if the conversion fails.
///
fn convert_to_sarif(results: &[Leak]) -> Result<String, serde_json::Error> {
    let mut run_results = vec![];
    for result in results {
        let location = json!({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": result.file
                },
                "region": {
                    "startLine": result.line_number,
                    "snippet": {
                        "text": result.line
                    }
                }
            }
        });

        let run_result = json!({
            "message": {
                "text": format!("{} {}", result.rule,"detected!")
            },
            "properties": {
                "commit": result.commit,
                "offender": result.offender,
                "date": result.date,
                "author": result.author,
                "email": result.email,
                "commitMessage": result.commit_message,

                "repo": result.repo
            },
            "locations": [location]
        });

        run_results.push(run_result);
    }

    let sarif_json = json!({
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Gitleaks",
                        "semanticVersion": "v6.2.0",
                        "rules": []
                    }
                },
                "results": run_results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif_json)
}

/// Writes a CSV report with the provided results to the specified file path.
///
/// # Arguments
///
/// * `file_path` - The file path where the CSV report will be written.
/// * `results` - A slice containing the `Leak` results to be written to the CSV.
///
/// # Returns
///
/// * `Result<(), Box<dyn Error>>` - Returns `Ok(())` if the CSV report is written successfully,
///   or an `Err` variant containing the error information.
pub fn write_csv_report(file_path: &str, results: &[Leak]) -> Result<(), Box<dyn Error>> {
    let mut data: Vec<CsvResult> = vec![];
    for leak in results {
        let item = CsvResult {
            repo: leak.repo.clone(),
            line_number: leak.line_number,
            line: leak.line.clone(),
            offender: leak.offender.clone(),
            commit: leak.commit.clone(),
            rule: leak.rule.clone(),
            commit_message: leak.commit_message.clone(),
            author: leak.author.clone(),
            email: leak.email.clone(),
            file: leak.file.clone(),
            date: leak.date.clone(),
        };
        data.push(item);
    }
    let file = File::create(file_path)?;
    let mut writer = Writer::from_writer(file);
    for item in data {
        writer.serialize(item)?;
    }
    writer.flush()?;

    Ok(())
}

/// Check if the provided `path` is in the allowlist of paths.
///
///
/// # Arguments
///
/// * `path` - The path to check against the allowlist paths.
/// * `allowlist_paths` - A slice of strings representing the allowlist paths.
///
/// # Returns
///
/// Returns `true` if the `path` is found in the allowlist paths, otherwise `false`.
///
pub fn is_path_in_allowlist(path: &str, allowlist_paths: &[String]) -> bool {
    for allowlist_path in allowlist_paths {
        if is_regex(allowlist_path) {
            let allowlist_regex = Regex::new(allowlist_path).unwrap();
            if allowlist_regex.is_match(path) {
                return true;
            }
        } else {
            for allowlist_path in allowlist_paths {
                if allowlist_path == path {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks if a commit is present in the allowlist of commits.
///
/// # Arguments
///
/// * `commit` - The commit to check.
/// * `allow_commits` - A slice containing the allowlist of commits.
///
/// # Returns
///
/// * `bool` - Returns `true` if the commit is found in the allowlist, otherwise `false`.
///
pub fn is_commit_in_allowlist(commit: &str, allow_commits: &[String]) -> bool {
    for allowlist_commit in allow_commits {
        if commit == allowlist_commit {
            return true;
        }
    }
    false
}

/// Check if the provided `test_string` matches any of the regular expressions in the `regex_array`.
///
/// # Arguments
///
/// * `regex_array` - A vector of regular expression strings to check against the `test_string`.
/// * `test_string` - The string to test against the regular expressions in `regex_array`.
///
/// # Returns
///
/// Returns `true` if the `test_string` matches any of the regular expressions in `regex_array`, otherwise `false`.
///
pub fn is_string_matched(regex_array: &[String], test_string: &str) -> bool {
    for regex_str in regex_array.iter() {
        let regex = Regex::new(regex_str).unwrap();
        if regex.is_match(test_string) {
            return true;
        }
    }
    false
}

/// Check if the provided `content` contains any of the strings in the given `array`. It is used to find stopswords.
///
/// # Arguments
///
/// * `array` - A vector of strings to check against the `content`.
/// * `content` - The string to check for the presence of any of the strings in `array`.
///
/// # Returns
///
/// Returns `true` if any of the strings in `array` is found in the `content`, otherwise `false`.
///
pub fn is_contains_strs(array: &[String], content: &str) -> bool {
    for item in array.iter() {
        if content.contains(item) {
            return true;
        }
    }
    false
}

/// Checks if a given text is a link.
///
/// # Arguments
///
/// * `text` - The text to check for links.
///
/// # Returns
///
/// * `bool` - Returns `true` if the text contains a link, otherwise `false`.
///
pub fn is_link(text: &str) -> bool {
    let re = Regex::new(r"(?i)\b((?:https?://|www\.)\S+)\b").unwrap();
    re.is_match(text)
}

/// Check if the given string is a regular expression.
///
///
/// # Arguments
///
/// * `s` - The string to check for regular expression syntax.
///
/// # Returns
///
/// Returns `true` if the string is a regular expression, otherwise `false`.
///
fn is_regex(s: &str) -> bool {
    //TODO: Improve regular expression check
    s.starts_with('(') && s.ends_with('$')&&!s.starts_with('/') 

}

/// Removes duplicates from `array1` based on the elements in `array2`.
///
/// # Arguments
///
/// * `array1` - The first vector containing elements to remove duplicates from.
/// * `array2` - The second vector used to determine the duplicates.
///
/// # Type Constraints
///
/// `T` must implement the `Eq`, `std::hash::Hash`, and `Clone` traits.
///
/// # Returns
///
/// Returns a new vector that contains the elements from `array1` without the duplicates
/// that are present in `array2`.
///
pub fn remove_duplicates<T: Eq + std::hash::Hash + Clone>(
    array1: Vec<T>,
    array2: Vec<T>,
) -> Vec<T> {
    let set: HashSet<_> = array2.into_iter().collect();
    array1.into_iter().filter(|x| !set.contains(x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    static CONFIG_FILE_PATH: &str = "examples/test_gitleaks.toml";

    fn mock_config_content() -> Value {
        toml::from_str::<Value>(
            r#"
            [[rules]]
            description = "Rule 1"
            id = "rule1"
            regex = "\\d+"
            entropy = 0.5
            keywords = ["keyword1", "keyword2"]

            [[rules]]
            description = "Rule 2"
            id = "rule2"
            regex = "[A-Z]+"
            entropy = 0.3
            keywords = ["keyword3"]

            [[rules]]
            description = "Rule 3"
            id = "rule3"
            regex = "[a-z]+"
            entropy = 0.2
            keywords = ["keyword4", "keyword5"]

            [[rules]]
            description = "Rule 4"
            id = "rule4"
            regex = "\\w+"
            entropy = 0.4
            keywords = ["keyword6"]
            "#,
        )
        .unwrap()
    }

    fn mock_leaks() -> Vec<Leak> {
        vec![Leak {
            line: "Sensitive information".to_string(),
            line_number: 42,
            offender: "John Doe".to_string(),
            commit: "abcd1234".to_string(),
            repo: "my-repo".to_string(),
            rule: "password_leak".to_string(),
            commit_message: "Fix security issue".to_string(),
            author: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            file: "path/to/file.txt".to_string(),
            date: "2023-05-30".to_string(),
        }]
    }
    #[test]
    fn test_load_config() {
        let result = load_config_file(CONFIG_FILE_PATH);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_allowlist_valid_config() {
        let result = config_allowlist(&mock_config_content());
        assert!(result.is_ok());
    }
    #[test]
    fn test_config_ruleslist_and_keywords() {
        let result = config_ruleslist_and_keywords(&mock_config_content());

        assert!(result.is_ok());
        let ruleslist = result.unwrap();

        assert_eq!(ruleslist.len(), 4);

        let rule1 = &ruleslist[0];
        assert_eq!(rule1.description, "Rule 1");
        assert_eq!(rule1.id, "rule1");
        assert_eq!(rule1.regex, "\\d+");
        assert_eq!(rule1.keywords, vec!["keyword1", "keyword2"]);
        assert!(rule1.allowlist.is_none());

        let rule2 = &ruleslist[1];
        assert_eq!(rule2.description, "Rule 2");
        assert_eq!(rule2.id, "rule2");
        assert_eq!(rule2.regex, "[A-Z]+");
        assert_eq!(rule2.keywords, vec!["keyword3"]);
        assert!(rule2.allowlist.is_none());

        let rule3 = &ruleslist[2];
        assert_eq!(rule3.description, "Rule 3");
        assert_eq!(rule3.id, "rule3");
        assert_eq!(rule3.regex, "[a-z]+");
        assert_eq!(rule3.keywords, vec!["keyword4", "keyword5"]);
        assert!(rule3.allowlist.is_none());

        let rule4 = &ruleslist[3];
        assert_eq!(rule4.description, "Rule 4");
        assert_eq!(rule4.id, "rule4");
        assert_eq!(rule4.regex, "\\w+");
        assert_eq!(rule4.keywords, vec!["keyword6"]);
        assert!(rule4.allowlist.is_none());
    }

    #[test]
    fn test_write_rule_to_toml() {
        let rule = Rule {
            description: "Adafruit API Key".to_string(),
            id: "adafruit-api-key".to_string(),
            regex: r#"(?i)(?:adafruit)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)"#.to_string(),
            keywords: vec!["adafruit".to_string()],
            allowlist: None,
        };
        let result = append_rule_to_toml(&rule, CONFIG_FILE_PATH);
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_rule_by_id() {
        if let Err(err) = delete_rule_by_id(CONFIG_FILE_PATH, "adafruit-api-key") {
            eprintln!("Error: {}", err);
        }
    }

     #[test]
    fn test_update_rule_by_id() {
        let rule = Rule {
            description: "11111111111".to_string(),
            id: "stripe-access-token".to_string(),
            regex: r#"(?i)(?:adafruit)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)"#.to_string(),
            keywords: vec!["adafruit".to_string()],
            allowlist: None,
        };
        let result = update_rule_by_id( CONFIG_FILE_PATH,&rule.id,&rule,);
       
         assert!(result.is_ok());
    }
    #[test]
    fn test_is_path_in_allowlist_regex_not_match() {
        let path = "/path/to/file.txt";
        let allowlist_paths = vec!["/other/.*\\.txt".to_string()];
        let result = is_path_in_allowlist(path, &allowlist_paths);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_path_in_allowlist_exact_match() {
        let path = "tests/files/gitleaks.toml";
        let allowlist_paths = vec!["tests/files/gitleaks.toml".to_string()];
        let result = is_path_in_allowlist(path, &allowlist_paths);
        assert_eq!(result, true);
    }

    #[test]
    fn test_is_string_matched_match() {
        let regex_array = vec!["^hello".to_string(), "world$".to_string()];
        let test_string = "hello, world!";
        let result = is_string_matched(&regex_array, test_string);
        assert_eq!(result, true);
    }

    #[test]
    fn test_is_string_matched_not_match() {
        let regex_array = vec!["^hello".to_string(), "world$".to_string()];
        let test_string = "goodbye";
        let result = is_string_matched(&regex_array, test_string);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_contains_strs_contains() {
        let array = vec![
            "apple".to_string(),
            "banana".to_string(),
            "orange".to_string(),
        ];
        let content = "I like to eat bananas";
        let result = is_contains_strs(&array, content);
        assert_eq!(result, true);
    }

    #[test]
    fn test_is_contains_strs_not_contains() {
        let array = vec![
            "apple".to_string(),
            "banana".to_string(),
            "orange".to_string(),
        ];
        let content = "I like to eat grapes";
        let result = is_contains_strs(&array, content);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_regex_valid_case() {
        let input = "(regex$";
        let result = is_regex(input);
        assert_eq!(result, true);
    }

    #[test]
    fn test_is_regex_invalid_case() {
        let input = "(regex";
        let result = is_regex(input);
        assert_eq!(result, false);
    }

    #[test]
    fn test_is_regex_empty_string() {
        let input = "";
        let result = is_regex(input);
        assert_eq!(result, false);
    }

    #[test]
    fn test_remove_duplicates() {
        // Test case 1
        let array1 = vec![1, 1, 2, 3, 4, 5];
        let array2 = vec![3, 4, 5, 6, 7];
        let result = remove_duplicates(array1, array2);
        assert_eq!(result, vec![1, 1, 2]);
    }

    #[test]
    fn test_is_link_with_valid_links() {
        assert!(is_link("https://www.example.com"));
        assert!(is_link("http://example.com"));
        assert!(is_link("www.example.com"));
        assert!(is_link("www.example.com/path"));
        assert!(is_link("www.example.com?q=query"));
    }

    #[test]
    fn test_is_link_with_invalid_links() {
        assert!(!is_link("example.com"));
        assert!(!is_link("example.com/path"));
        assert!(!is_link("example.com?q=query"));
        assert!(!is_link("not a link"));
    }

    // test report functions
    #[test]
    fn test_write_json_report() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_str().unwrap();

        write_json_report(file_path, &&mock_leaks()).unwrap();

        let json_content = fs::read_to_string(file_path).unwrap();

        assert!(json_content.contains("Sensitive information"));
        assert!(json_content.contains("path/to/file.txt"));
    }

    #[test]
    fn test_write_sarif_report() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_str().unwrap();

        write_sarif_report(file_path, &mock_leaks()).unwrap();

        let sarif_content = fs::read_to_string(file_path).unwrap();

        assert!(sarif_content.contains("Sensitive information"));
        assert!(sarif_content.contains("path/to/file.txt"));
        
    }

    #[test]
    fn test_write_csv_report() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_str().unwrap();

        write_csv_report(file_path, &&mock_leaks()).unwrap();

        let csv_content = fs::read_to_string(file_path).unwrap();

        assert!(csv_content.contains("Sensitive information"));
        assert!(csv_content.contains("path/to/file.txt"));
    }
}
