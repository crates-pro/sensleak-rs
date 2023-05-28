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

**Note: This project is currently under development. The following features describe sensitive information search within a local folder.**

```shell
sensleaks-rs

Usage: sensleak.exe [OPTIONS] --repo <REPO>

Options:
      --repo <REPO>                  Target repository
      --config <CONFIG>              Config path.. [default: gitleaks.toml]
      --report <REPORT>              Path to write json leaks file [default: ]
  -v, --verbose                      Show verbose output from scan
      --pretty                       Pretty print json if leaks are present
      --commit <COMMIT>              sha of commit to scan or "latest" to scan the last commit of the repository
      --commits <COMMITS>            comma separated list of a commits to scan
      --commits-file <COMMITS_FILE>  file of new line separated list of a commits to scan
      --commit-since <COMMIT_SINCE>  Scan commits more recent than a specific date. Ex: '2006-01-02' or '2023-01-02T15:04:05-0700' format
      --commit-until <COMMIT_UNTIL>  Scan commits older than a specific date. Ex: '2006-01-02' or '2006-10-02T15:04:05-0700' format
      --commit-from <COMMIT_FROM>    Commit to start scan from
      --commit-to <COMMIT_TO>        Commit to stop scan
      --branch <BRANCH>              Branch to scan (comming soon)
      --uncommitted                  run gitleaks on uncommitted code (comming soon)
      --user <USER>                  user to scan (comming soon)
  -h, --help                         Print help (see more with '--help')
  -V, --version                      Print version



Repository: https://github.com/open-rust-initiative/sensleak-rs
```

Examples: (Test repo: https://github.com/sonichen/TestGitOperation)

```shell
sensleak --repo="D:/Workplace/Git/TestGitOperation" --commit="8bdca802af0514ce29947e20c6be1719974ad866" -v --pretty
```

Output:

```shell
[INFO][2023-05-26 11:51:04] Open repo ...
[
    Leak {
        line: "twilio_api_key = SK12345678901234567890123456789012",
        line_number: 6,
        secret: "api_key = SK12345678901234567890123456789012",
        entropy: "3.5",
        commit: "8bdca802af0514ce29947e20c6be1719974ad866",
        repo: "TestGitOperation",
        rule: "Generic API Key",
        commit_message: "test\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/src/key.java",
        date: "2023-05-23 23:55:12 -08:00",
        tags: "",
        operation: "addition",
    },
   ...
    Leak {
        line: "twilio_api_key = SK12345678901234567890123456789012",
        line_number: 2,
        secret: "SK12345678901234567890123456789012",
        entropy: "",
        commit: "8bdca802af0514ce29947e20c6be1719974ad866",
        repo: "TestGitOperation",
        rule: "Twilio API Key",
        commit_message: "test\n",
        author: "sonichen",
        email: "1606673007@qq.com",
        file: "/src/mykey.java",
        date: "2023-05-23 23:55:12 -08:00",
        tags: "",
        operation: "addition",
    },
]
[WARN][2023-05-26 11:51:05]10 leaks detected. 1 commits scanned in 1.7318395s

```



More examples:

```shell
cargo run -- --repo="D:/Workplace/Git/TestGitOperation" --commit="8bdca802af0514ce29947e20c6be1719974ad866" -v --pretty
cargo run -- --repo="D:/Workplace/Git/TestGitOperation" --commits="4362fc4df48df74a46b56368d7fff1b02d01be72,8bdca802af0514ce29947e20c6be1719974ad866" -v --pretty
cargo run -- --repo="D:/Workplace/Git/TestGitOperation" --commits-file="tests/files/commits.txt" -v --pretty
cargo run -- --repo="D:/Workplace/Git/TestGitOperation" --commit-since="2023-05-20" --commit-until="2023-05-26"   -v --pretty
cargo run -- --repo="D:/Workplace/Git/TestGitOperation" --commit-to="4362fc4df48df74a46b56368d7fff1b02d01be72" --commit-from="8bdca802af0514ce29947e20c6be1719974ad866"  -v --pretty
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
