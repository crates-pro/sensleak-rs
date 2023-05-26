# sensleak-rs

sensleak-rs is developing a detect tool  similar to gitleaks using Rust, which will detecting hardcoded secrets like passwords, api keys, and tokens in git repos. 

## Background

Many developers store sensitive information such as keys and certificates in their code, which poses security risks. Therefore, there are commercial services like GitGuardian scanning GitHub and GitLab, as well as open-source components like truffleHog and Gitleaks that support similar functionalities.

### Requirements

Develop a Git repository sensitive data detection tool using the Rust programming language.

1. Develop in Rust for improved security.
2. Command-line tool that outputs a test report.
3. Support running as a service and provide access control through a REST API.

### Environment

- Runs on X86_64 and ARM64 architectures.
- Uses Rust Edition 2021.

## Usage

Here are a few examples of how to use the tool in different scenarios:

- Running the tool in the command-line interface (CLI) to perform sensitive data checks.

**Note: This project is currently under development. **

```shell
Usage: sensleak.exe [OPTIONS] --repo <REPO>

Options:
      --repo <REPO>                    Target repository
      --config <CONFIG>                Config path [default: gitleaks.toml]
      --report <REPORT>                Path to write json leaks file [default: ]
      --report-format <REPORT_FORMAT>  json, csv, sarif [default: json]
  -v, --verbose                        Show verbose output from scan
      --pretty                         Pretty print json if leaks are present
      --commit <COMMIT>                sha of commit to scan or "latest" to scan the last commit of the repository
      --commits <COMMITS>              comma separated list of a commits to scan
      --commits-file <COMMITS_FILE>    file of new line separated list of a commits to scan
      --commit-since <COMMIT_SINCE>    Scan commits more recent than a specific date. Ex: '2006-01-02' or '2023-01-02T15:04:05-0700' format
      --commit-until <COMMIT_UNTIL>    Scan commits older than a specific date. Ex: '2006-01-02' or '2006-10-02T15:04:05-0700' format
      --commit-from <COMMIT_FROM>      Commit to start scan from
      --commit-to <COMMIT_TO>          Commit to stop scan
      --branch <BRANCH>                Branch to scan
      --uncommitted <UNCOMMITTED>      Run sensleak on uncommitted code [possible values: true, false]
      --user <USER>                    Set user to scan [default: ]
      --repo-config                    Load config from target repo. Config file must be ".gitleaks.toml" or "gitleaks.toml"
      --debug                          log debug messages
      --disk <DISK>                    Clones repo(s) to disk
  -h, --help                           Print help (see more with '--help')
  -V, --version                        Print version

Repository: https://github.com/open-rust-initiative/sensleak-rs
```

Examples: 

```shell
sensleak --repo="https://github.com/sonichen/TestGitOperation.git" -v --pretty --commit="140cef166cd8ba98201d9cad80289a75cd590cec"
```

Output:

```shell
[INFO][2023-06-01 09:16:02] Clone repo ...
[
    Leak {
        line: "twilio_api_key = SK12345678901234567890123456789012",
        line_number: 6,
        offender: "api_key = SK12345678901234567890123456789012",
        commit: "140cef166cd8ba98201d9cad80289a75cd590cec",
        repo: "TestGitOperation",
        rule: "Generic API Key",
        commit_message: "Merge pull request #1 from sonichen/secret\n\nSecret",
        author: "sonichen",
        email: "57282299+sonichen@users.noreply.github.com",
        file: "/src/key.java",
        date: "2023-05-27 04:28:55 -08:00",
        tags: "",
        operation: "addition",
    },
    Leak {
        line: "Vault Service Token = hvs.abcdefghijklmn1234567890opqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        line_number: 8,
        offender: "Token = hvs.abcdefghijklmn1234567890opqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        commit: "140cef166cd8ba98201d9cad80289a75cd590cec",
        repo: "TestGitOperation",
        rule: "Generic API Key",
        commit_message: "Merge pull request #1 from sonichen/secret\n\nSecret",
        author: "sonichen",
        email: "57282299+sonichen@users.noreply.github.com",
        file: "/src/key.java",
        date: "2023-05-27 04:28:55 -08:00",
        tags: "",
        operation: "addition",
    },
    Leak {
        line: " 网址 = https://hooks.slack.com/workflows/B01234567/T01234567/abcdefghijklmnopqrstuvwx",
        line_number: 7,
        offender: "https://hooks.slack.com/workflows/B01234567/T01234567/abcdefghijklmnopqrstuvwx",
        commit: "140cef166cd8ba98201d9cad80289a75cd590cec",
        repo: "TestGitOperation",
        rule: "Slack Webhook",
        commit_message: "Merge pull request #1 from sonichen/secret\n\nSecret",
        author: "sonichen",
        email: "57282299+sonichen@users.noreply.github.com",
        file: "/src/key.java",
        date: "2023-05-27 04:28:55 -08:00",
        tags: "",
        operation: "addition",
    },
   ...
]
[WARN][2023-06-01 09:16:03]10 leaks detected. 1 commits scanned in 1.6758691s

```



- Accessing the tool's functionality through the REST API for access control and data scanning. (Coming soon...)

## Configuration

Use the [gitleaks configuration](https://github.com/gitleaks/gitleaks#configuration) in this project.

## Document

Run the following code to read the project document.

```shell
cargo doc --document-private-items --open
```

## Contributing

The  project relies on community contributions and aims to simplify getting  started. To use sensleak-rs, clone the repo, install dependencies, and run  sensleak-rs. Pick an issue, make changes, and submit a pull request for community review.

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
