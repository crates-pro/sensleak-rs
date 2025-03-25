# sensleak - scan git repo secrets

sensleak is a Rust-based tool that scans Git repositories for sensitive data, specifically targeting sensitive information such as passwords, API keys, certificates, and private keys embedded within code. 

## Background

Many developers store sensitive information such as keys and certificates in their code, which poses security risks. Therefore, there are commercial services like GitGuardian scanning GitHub and GitLab, as well as open-source components like truffleHog and Gitleaks that support similar functionalities.

## Feature 

- **Enhanced Security.** Develop the tool in Rust to ensure improved security and memory safety.
- **Command-line Interface**. Create a user-friendly command-line tool that generates a comprehensive test report.
- **REST API with Access Control**. Enable the tool to run as a service and provide access control through a REST API. Utilize Swagger to generate API documentation.
- **Concurrent Scanning**. Utilize a thread pool to control concurrent scanning of secrets, thereby improving overall efficiency.
- **Batch Processing**. Implement batch processing of files to further optimize the scanning process and enhance efficiency.

## Technology

- Development Language: Rust
- Command-line Interaction: [clap.rs](https://github.com/clap-rs/clap)
- Git Repository Operations: [git2](https://github.com/rust-lang/git2-rs)
- Web Framework: [actix-web](https://actix.rs)
- Auto-generated OpenAPI Documentation: [utoipa](https://github.com/juhaku/utoipa)

## Usage

### CLI Usage

Running the tool in the command-line interface (CLI) to perform sensitive data checks.

```
cargo run --bin scan -- -help
```

```shell
Usage: scan [OPTIONS] --repo <REPO>

Options:
      --repo <REPO>                    Target repository
      --config <CONFIG>                Config path [default: gitleaks.toml]
      --threads <THREADS>              Maximum number of threads sensleak spawns [default: 10]
      --chunk <CHUNK>                  The number of files processed in each batch [default: 10]
      --report <REPORT>                Path to write json leaks file
      --report-format <REPORT_FORMAT>  json, csv, sarif [default: json]
  -v, --verbose                        Show verbose output from scan
      --pretty                         Pretty print json if leaks are present
      --commit <COMMIT>                sha of commit to scan
      --commits <COMMITS>              comma separated list of a commits to scan
      --commits-file <COMMITS_FILE>    file of new line separated list of a commits to scan
      --commit-since <COMMIT_SINCE>    Scan commits more recent than a specific date. Ex: '2006-01-02' or '2023-01-02T15:04:05-0700' format
      --commit-until <COMMIT_UNTIL>    Scan commits older than a specific date. Ex: '2006-01-02' or '2006-10-02T15:04:05-0700' format
      --commit-from <COMMIT_FROM>      Commit to start scan from
      --commit-to <COMMIT_TO>          Commit to stop scan
      --branch <BRANCH>                Branch to scan
      --uncommitted                    Run sensleak on uncommitted code
      --user <USER>                    Set user to scan [default: ]
      --repo-config                    Load config from target repo. Config file must be ".gitleaks.toml" or "gitleaks.toml"
      --debug                          log debug messages
      --disk <DISK>                    Clones repo(s) to disk
      --to-db                          Output to database
  -h, --help                           Print help (see more with '--help')
  -V, --version                        Print version

run 'cargo run --bin api' to get REST API.
Repository: https://github.com/open-rust-initiative/sensleak-rs

```

Example: 

Test https://github.com/sonichen/Expiry-Reminder-Assistant.git

```shell
$ cargo run --bin scan -- --repo="D:/Workplace/Java/project/ExpiryReminderAssistant" -v --pretty
```

```shell
[INFO][2023-06-05 09:59:59] Clone repo ...
[
    Leak {
        line: "        String secret = \"1708b0314f18f420d3fe8128652af43c\"; //自己小程序的SECRET",
        line_number: 67,
        offender: "secret = \"1708b0314f18f420d3fe8128652af43c\"",
        commit: "410eb5a84408d3e63edb4d0975e5516e56f6ea6a",
        repo: "ExpiryReminderAssistant",
        rule: "Generic API Key",
        commit_message: "submit code\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/backend/src/main/java/com/cyj/controller/login/WXLoginController.java",
        date: "2023-05-31 18:09:42 -08:00",
    },
    Leak {
        line: "        businessException.apiResponse = apiResponse;",
        line_number: 64,
        offender: "apiResponse = apiResponse;",
        commit: "410eb5a84408d3e63edb4d0975e5516e56f6ea6a",
        repo: "ExpiryReminderAssistant",
        rule: "Generic API Key",
        commit_message: "submit code\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/backend/src/main/java/com/cyj/exception/BusinessException.java",
        date: "2023-05-31 18:09:42 -08:00",
    },
    Leak {
        line: "//    app_secret:bm92ZWk2WFdoR3RkV3ZiUk5SUnVXUT09",
        line_number: 5,
        offender: "secret:bm92ZWk2WFdoR3RkV3ZiUk5SUnVXUT09",
        commit: "410eb5a84408d3e63edb4d0975e5516e56f6ea6a",
        repo: "ExpiryReminderAssistant",
        rule: "Generic API Key",
        commit_message: "submit code\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/backend/src/main/java/com/cyj/utils/constants/DevelopConstants.java",
        date: "2023-05-31 18:09:42 -08:00",
    },
    Leak {
        line: "    public static final String  APP_SECRET=\"bm92ZWk2WFdoR3RkV3ZiUk5SUnVXUT09\";",
        line_number: 7,
        offender: "SECRET=\"bm92ZWk2WFdoR3RkV3ZiUk5SUnVXUT09\"",
        commit: "410eb5a84408d3e63edb4d0975e5516e56f6ea6a",
        repo: "ExpiryReminderAssistant",
        rule: "Generic API Key",
        commit_message: "submit code\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/backend/src/main/java/com/cyj/utils/constants/DevelopConstants.java",
        date: "2023-05-31 18:09:42 -08:00",
    },
    Leak {
        line: "//    public static final String APPSECRET = \"94f391d306875101822ffa1b2c3cff09\";",
        line_number: 17,
        offender: "SECRET = \"94f391d306875101822ffa1b2c3cff09\"",
        commit: "410eb5a84408d3e63edb4d0975e5516e56f6ea6a",
        repo: "ExpiryReminderAssistant",
        rule: "Generic API Key",
        commit_message: "submit code\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/backend/src/main/java/com/cyj/utils/secret/AuthUtil.java",
        date: "2023-05-31 18:09:42 -08:00",
    },
    Leak {
        line: "  secret: \"c6e1180dda3eaca49f3d7ed912718e4d\"   #小程序密钥",
        line_number: 36,
        offender: "secret: \"c6e1180dda3eaca49f3d7ed912718e4d\"",
        commit: "410eb5a84408d3e63edb4d0975e5516e56f6ea6a",
        repo: "ExpiryReminderAssistant",
        rule: "Generic API Key",
        commit_message: "submit code\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/backend/src/main/resources/application.yaml",
        date: "2023-05-31 18:09:42 -08:00",
    },
    Leak {
        line: "  secret: \"c6e1180dda3eaca49f3d7ed912718e4d\"   #小程序密钥",
        line_number: 36,
        offender: "secret: \"c6e1180dda3eaca49f3d7ed912718e4d\"",
        commit: "410eb5a84408d3e63edb4d0975e5516e56f6ea6a",
        repo: "ExpiryReminderAssistant",
        rule: "Generic API Key",
        commit_message: "submit code\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/backend/target/classes/application.yaml",
        date: "2023-05-31 18:09:42 -08:00",
    },
]
[WARN][2023-06-05 10:00:02]7 leaks detected. 1 commits scanned in 1.2538834s
```

### API Document

Run the following code to read the project document.

```shell
cargo run --bin api
```

The API document is located at http://localhost:7000/swagger-ui/#/

### Project Document

Run the following code to read the project document.

```shell
cargo doc --document-private-items --open
```

### Configuration

Use the [gitleaks configuration](https://github.com/gitleaks/gitleaks#configuration) in this project. The difference is that in this project, the paths need to start with a "/".

```toml
# Title for the gitleaks configuration file.
title = "Gitleaks title"

# Extend the base (this) configuration. When you extend a configuration
# the base rules take precedence over the extended rules. I.e., if there are
# duplicate rules in both the base configuration and the extended configuration
# the base rules will override the extended rules.
# Another thing to know with extending configurations is you can chain together
# multiple configuration files to a depth of 2. Allowlist arrays are appended
# and can contain duplicates.
# useDefault and path can NOT be used at the same time. Choose one.
[extend]
# useDefault will extend the base configuration with the default gitleaks config:
# https://github.com/zricethezav/gitleaks/blob/master/config/gitleaks.toml
useDefault = true
# or you can supply a path to a configuration. Path is relative to where gitleaks
# was invoked, not the location of the base config.
path = "common_config.toml"

# An array of tables that contain information that define instructions
# on how to detect secrets
[[rules]]

# Unique identifier for this rule
id = "awesome-rule-1"

# Short human readable description of the rule.
description = "awesome rule 1"

# Golang regular expression used to detect secrets. Note Golang's regex engine
# does not support lookaheads.
regex = '''one-go-style-regex-for-this-rule'''

# Golang regular expression used to match paths. This can be used as a standalone rule or it can be used
# in conjunction with a valid `regex` entry.
path = '''a-file-path-regex'''

# Array of strings used for metadata and reporting purposes.
tags = ["tag","another tag"]

# Int used to extract secret from regex match and used as the group that will have
# its entropy checked if `entropy` is set.
secretGroup = 3

# Float representing the minimum shannon entropy a regex group must have to be considered a secret.
entropy = 3.5

# Keywords are used for pre-regex check filtering. Rules that contain
# keywords will perform a quick string compare check to make sure the
# keyword(s) are in the content being scanned. Ideally these values should
# either be part of the idenitifer or unique strings specific to the rule's regex
# (introduced in v8.6.0)
keywords = [
  "auth",
  "password",
  "token",
]

# You can include an allowlist table for a single rule to reduce false positives or ignore commits
# with known/rotated secrets
[rules.allowlist]
description = "ignore commit A"
commits = [ "commit-A", "commit-B"]
paths = [
  '''\go\.mod''',
  '''\go\.sum'''
]
# note: (rule) regexTarget defaults to check the _Secret_ in the finding.
# if regexTarget is not specified then _Secret_ will be used.
# Acceptable values for regexTarget are "match" and "line"
regexTarget = "match"
regexes = [
  '''process''',
  '''getenv''',
]
# note: stopwords targets the extracted secret, not the entire regex match
# like 'regexes' does. (stopwords introduced in 8.8.0)
stopwords = [
  '''client''',
  '''endpoint''',
]


# This is a global allowlist which has a higher order of precedence than rule-specific allowlists.
# If a commit listed in the `commits` field below is encountered then that commit will be skipped and no
# secrets will be detected for said commit. The same logic applies for regexes and paths.
[allowlist]
description = "global allow list"
commits = [ "commit-A", "commit-B", "commit-C"]
paths = [
  '''gitleaks\.toml''',
  '''(.*?)(jpg|gif|doc)'''
]

# note: (global) regexTarget defaults to check the _Secret_ in the finding.
# if regexTarget is not specified then _Secret_ will be used.
# Acceptable values for regexTarget are "match" and "line"
regexTarget = "match"

regexes = [
  '''219-09-9999''',
  '''078-05-1120''',
  '''(9[0-9]{2}|666)-\d{2}-\d{4}''',
]
# note: stopwords targets the extracted secret, not the entire regex match
# like 'regexes' does. (stopwords introduced in 8.8.0)
stopwords = [
  '''client''',
  '''endpoint''',
]
```

## Contributing

The  project relies on community contributions and aims to simplify getting  started. To use sensleak, clone the repo, install dependencies, and run  sensleak. Pick an issue, make changes, and submit a pull request for community review.

To contribute to rkos, you should:

- Familiarize yourself with the [Code of Conduct](https://github.com/open-rust-initiative/rkos/blob/main/CODE-OF-CONDUCT.md). sensleak-rs has a strict policy against abusive, unethical, or illegal behavior.
- Review the [Contributing Guidelines](https://github.com/open-rust-initiative/rkos/blob/main/CONTRIBUTING.md). This document outlines the process for submitting bug reports, feature requests, and pull requests to sensleak-rs.
- Sign the [Developer Certificate of Origin](https://developercertificate.org) (DCO) by adding a `Signed-off-by` line to your commit messages. This certifies that you wrote or have the right to submit the code you are contributing to the project.
- Choose an issue to work on. Issues labeled `good first issue` are suitable for newcomers. You can also look for issues marked `help wanted`.
- Fork the sensleak-rs repository and create a branch for your changes.
- Make your changes and commit them with a clear commit message.
- Push your changes to GitHub and open a pull request.
- Respond to any feedback on your pull request. The sensleak-rs maintainers  will review your changes and may request modifications before merging.
- Once your pull request is merged, you will be listed as a contributor in the project repository and documentation.

To comply with the requirements, contributors must include both a `Signed-off-by` line and a PGP signature in their commit messages. You can find more information about how to generate a PGP key [here](https://docs.github.com/en/github/authenticating-to-github/managing-commit-signature-verification/generating-a-new-gpg-key).

Git even has a `-s` command line option to append this automatically to your commit message, and `-S` to sign your commit with your PGP key. For example:

```shell
$ git commit -S -s -m 'This is my commit message'
```

## License

sensleak-rs is licensed under this licensed:

- MIT LICENSE (  https://opensource.org/licenses/MIT)

## References

1. [What is Gitleaks and how to use it?](https://akashchandwani.medium.com/what-is-gitleaks-and-how-to-use-it-a05f2fb5b034)
2. [Gitleaks.tools](https://github.com/gitleaks/gitleaks)
