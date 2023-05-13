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
  -r, --repo <REPO>      Target repository
  -c, --config <CONFIG>  Config path.. [default: gitleaks.toml]
  -o, --report <REPORT>  Path to write json leaks file [default: ]
  -v, --verbose          Show verbose output from scan
  -p, --pretty           Pretty print json if leaks are present
  -h, --help             Print help (see more with '--help')
  -V, --version          Print version

Repository: https://github.com/open-rust-initiative/sensleak-rs
```

Examples: (test the file in src\tests\files\test)

```shell
sensleak -r="tests\files\test" -v -e
```

Output:

```shell
[
    OutputItem {
        line: "token = sk_test_abcd1234567890efghijklmno",
        line_number: 5,
        secret: "sk_test_abcd1234567890efghijklmno",
        entropy: "",
        commit: "",
        repo: "",
        rule: "Stripe Access Token",
        commit_message: "",
        author: "",
        email: "",
        file: "tests\\files\\test\\file2.txt",
        date: "",
        tags: "",
        operation: "",
    },
    OutputItem {
        line: "twilio_api_key = SK12345678901234567890123456789012",
        line_number: 6,
        secret: "SK12345678901234567890123456789012",
        entropy: "",
        commit: "",
        repo: "",
        rule: "Twilio API Key",
        commit_message: "",
        author: "",
        email: "",
        file: "tests\\files\\test\\file2.txt",
        date: "",
        tags: "",
        operation: "",
    },
    ....
]
WARN:[2023-05-17 09:45:07]10 leaks detected. XXX commits scanned in 66.6222ms
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
