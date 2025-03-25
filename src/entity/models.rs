use chrono::{DateTime, FixedOffset};
use clap::Parser;
use serde::{Deserialize, Serialize};
use utoipa::{ToSchema};
use sea_orm::{entity::prelude::*, ActiveValue};
/// Represents the configuration for sensleaks tool.
#[derive(Parser, Debug)]
#[command(
    author = "yjchen",
    version = "0.3.0",
    about = "sensleaks-rs",
    long_about = "sensleaks: A tool to detect sensitive information in Git repository",
    after_help = "run 'cargo run --bin api' to get REST API.\nRepository: https://github.com/open-rust-initiative/sensleak-rs"
)]
#[derive(Deserialize, Serialize)]
pub struct Config {
    /// Target repository.
    #[arg(long)]
    pub repo: String,

    /// Config path
    #[arg(long, default_value = "gitleaks.toml")]
    pub config: String,

    /// Maximum number of threads sensleak spawns
    #[arg(long, default_value = "10")]
    pub threads: Option<usize>,

    /// The number of files processed in each batch
    #[arg(long, default_value = "10")]
    pub chunk: Option<usize>,

    /// Path to write json leaks file.
    #[arg(long)]
    pub report: Option<String>,

    /// json, csv, sarif
    #[arg(long, default_value = "json")]
    pub report_format: Option<String>,

    /// Show verbose output from scan.
    #[arg(short, long, default_value = "false")]
    pub verbose: bool,

    /// Pretty print json if leaks are present.
    #[arg(long, default_value = "false")]
    pub pretty: bool,

    /// sha of commit to scan
    #[arg(long)]
    pub commit: Option<String>,

    /// comma separated list of a commits to scan
    #[arg(long)]
    pub commits: Option<String>,

    /// file of new line separated list of a commits to scan
    #[arg(long)]
    pub commits_file: Option<String>,

    /// Scan commits more recent than a specific date. Ex: '2006-01-02' or '2023-01-02T15:04:05-0700' format.
    #[arg(long)]
    pub commit_since: Option<String>,

    /// Scan commits older than a specific date. Ex: '2006-01-02' or '2006-10-02T15:04:05-0700' format.
    #[arg(long)]
    pub commit_until: Option<String>,

    /// Commit to start scan from
    #[arg(long)]
    pub commit_from: Option<String>,

    /// Commit to stop scan
    #[arg(long)]
    pub commit_to: Option<String>,

    /// Branch to scan
    #[arg(long)]
    pub branch: Option<String>,

    /// Run sensleak on uncommitted code
    #[arg(long, default_value = "false")]
    // pub uncommitted: bool ,
    pub uncommitted: bool,

    /// Set user to scan
    #[arg(long, default_value = "")]
    pub user: Option<String>,

    /// Load config from target repo. Config file must be ".gitleaks.toml" or "gitleaks.toml"
    #[arg(long)]
    pub repo_config: bool,

    /// log debug messages.
    #[arg(long, default_value = "false")]
    pub debug: bool,

    /// Clones repo(s) to disk.
    #[arg(long)]
    pub disk: Option<String>,

    /// Output to database
    #[arg(long)]
    pub to_db: bool,
    // /// Start API
    // #[arg(long, default_value = "false")]
    // pub api: bool,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            repo: String::default(),
            config: String::from("gitleaks.toml"),
            threads: Some(50),
            chunk: Some(10),
            report: None,
            report_format: Some(String::from("json")),
            verbose: false,
            pretty: false,
            commit: None,
            commits: None,
            commits_file: None,
            commit_since: None,
            commit_until: None,
            commit_from: None,
            commit_to: None,
            branch: None,
            uncommitted: false,
            user: Some("".to_string()),
            repo_config: false,
            debug: false,
            disk: None,
            to_db: false,
            // api: false,
        }
    }
}

/// # An array of tables that contain information that define instructions on how to detect secrets.
#[derive(Debug, Serialize, Clone, Deserialize,ToSchema)]
pub struct Rule {
    /// Short human readable description of the rule.
    pub description: String,

    /// Unique identifier for this rule.
    pub id: String,

    /// Regular expression used to detect secrets.
    pub regex: String,

    /// Float representing the minimum shannon entropy a regex group must have to be considered a secret.
    // pub entropy: Option<f64>,

    /// Keywords are used for pre-regex check filtering. Rules that contain keywords will perform a quick string compare check to make sure the keyword(s) are in the content being scanned. Ideally these values should either be part of the idenitifer or unique strings specific to the rule's regex
    pub keywords: Vec<String>,

    /// You can include an allowlist table for a single rule to reduce false positives or ignore commits with known/rotated secrets.
    pub allowlist: Option<Allowlist>,
}

impl Rule {
    pub fn new() -> Rule {
        Rule {
            description: String::from("11"),
            id: String::from("11"),
            regex: String::from("(?i)(?:key|api|token|secret|client|passwd|password|auth|access)"),
            // entropy: Some(3.1),
            keywords: Vec::new(),
            allowlist: None,
        }
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self::new()
    }
}

/// Skip the allowlist
#[derive(Debug, Deserialize, Serialize, Clone,ToSchema)]
pub struct Allowlist {
    /// Skip the paths.
    pub paths: Vec<String>,

    /// Skip the commits.
    pub commits: Vec<String>,

    /// Acceptable values for regexTarget are "match" and "line".
    pub regex_target: String,

    /// Skip the secrets that satisfy the regexes.
    pub regexes: Vec<String>,

    /// Skip the secrets that contain the stopwords.
    pub stopwords: Vec<String>,
}
impl Allowlist {
    pub fn new() -> Allowlist {
        Allowlist {
            paths: Vec::new(),
            commits: Vec::new(),
            regex_target: String::from("match"),
            regexes: Vec::new(),
            stopwords: Vec::new(),
        }
    }
}
impl Default for Allowlist {
    fn default() -> Self {
        Self::new()
    }
}

/// Sea-orm Entity
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "leaks")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub line: String,
    pub line_number: u32,
    pub offender: String,
    pub commit: String,
    pub repo: String,
    pub rule: String,
    pub commit_message: String,
    pub author: String,
    pub email: String,
    pub file: String,
    pub date: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Represents an item in the scanned output.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Leak {
    /// The line containing the sensitive information.
    pub line: String,

    /// The line number where the sensitive information is found.
    pub line_number: u32,

    /// The sensitive information detected.
    pub offender: String,

    /// The commit info.
    pub commit: String,

    /// The repository where the sensitive information is found.
    pub repo: String,

    /// The rule used to detect the sensitive information.
    pub rule: String,

    /// The commit message associated with the sensitive information.
    pub commit_message: String,

    /// The author of the commit.
    pub author: String,

    /// The email of the commit author.
    pub email: String,

    /// The file path where the sensitive information is found.
    pub file: String,

    /// The date of the commit.
    pub date: String,
}

impl Leak {
    pub fn to_active_model(&self) -> ActiveModel {
        ActiveModel {
            line: ActiveValue::set(self.line.clone()),
            line_number: ActiveValue::set(self.line_number),
            offender: ActiveValue::set(self.offender.clone()),
            commit: ActiveValue::set(self.commit.clone()),
            repo: ActiveValue::set(self.repo.clone()),
            rule: ActiveValue::set(self.rule.clone()),
            commit_message: ActiveValue::set(self.commit_message.clone()),
            author: ActiveValue::set(self.author.clone()),
            email: ActiveValue::set(self.email.clone()),
            file: ActiveValue::set(self.file.clone()),
            date: ActiveValue::set(self.date.clone()),
            ..Default::default()
        }
    }
}

/// The scan condition
#[derive(Debug, Clone)]
pub struct Scan {
    /// allow list
    pub allowlist: Allowlist,

    /// the rules list
    pub ruleslist: Vec<Rule>,

    pub threads: Option<usize>,
    pub chunk: Option<usize>,
}
impl Scan {
    pub fn new() -> Self {
        Scan {
            allowlist: Allowlist::new(),
            ruleslist: Vec::new(),
            // keywords:Vec::new(),
            threads: Some(10),
            chunk: Some(10),
        }
    }
}

impl Default for Scan {
    fn default() -> Self {
        Self::new()
    }
}

/// The commit info
#[derive(Debug, Clone)]
pub struct CommitInfo {
    /// repo name
    pub repo: String,

    /// commit id
    pub commit: git2::Oid,

    /// author name
    pub author: String,

    /// the email of author
    pub email: String,

    /// commit message
    pub commit_message: String,

    /// commit date
    pub date: DateTime<FixedOffset>,

    /// file
    pub files: Vec<(String, String)>,
}

/// The Results of the project
#[derive(Debug)]
pub struct Results {
    /// The number of commits being scanned
    pub commits_number: usize,

    /// The leaks
    pub outputs: Vec<Leak>,
}
impl Results {
    pub fn new() -> Self {
        Results {
            commits_number: 0,
            outputs: Vec::new(),
        }
    }
}
impl Default for Results {
    fn default() -> Self {
        Self::new()
    }
}
/// CSV Object
#[derive(Debug, Serialize, Deserialize)]
pub struct CsvResult {
    /// The line containing the sensitive information.
    pub line: String,

    /// The line number where the sensitive information is found.
    pub line_number: u32,

    /// The sensitive information detected.
    pub offender: String,

    /// The commit info.
    pub commit: String,

    /// The repository where the sensitive information is found.
    pub repo: String,

    /// The rule used to detect the sensitive information.
    pub rule: String,

    /// The commit message associated with the sensitive information.
    pub commit_message: String,

    /// The author of the commit.
    pub author: String,

    /// The email of the commit author.
    pub email: String,

    /// The file path where the sensitive information is found.
    pub file: String,

    /// The date of the commit.
    pub date: String,
}

/// Config to connect to the database
#[derive(Debug, Default,Serialize, Deserialize)]
pub struct ConnectDbConfig {
    /// The host of the database
    pub host: String,
    /// The user of the database
    pub user: String,
    /// The password of the database
    pub password: String,
    /// The name of the database
    pub dbname: String,
    /// The port of the database
    pub port: String,
}

impl ConnectDbConfig {
    /// Translate the config to connection url
    pub fn to_connection_url(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}",
            self.user, self.password, self.host, self.port, self.dbname
        )
    }
    pub fn new() -> Self {
        ConnectDbConfig {
            host: String::from(""),
            user: String::from(""),
            password: String::from(""),
            dbname: String::from(""),
            port: String::from(""),
        }
    }
}
