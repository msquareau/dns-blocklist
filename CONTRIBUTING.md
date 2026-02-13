# Contributing to DNS Blocklist Compiler

Thank you for your interest in contributing! This document explains how to get involved.

## Reporting Bugs

Found a bug? Please [open a bug report](https://github.com/msquareau/dns-blocklist/issues/new?template=bug_report.yml). Fill out all required fields so we can reproduce the issue.

## Suggesting Features

Have an idea? Please [open a feature request](https://github.com/msquareau/dns-blocklist/issues/new?template=feature_request.yml).

## Development Setup

1. Install [Rust](https://www.rust-lang.org/tools/install) 1.75 or later.
2. Clone the repo and build:

```bash
git clone https://github.com/msquareau/dns-blocklist.git
cd dns-blocklist
cargo build
cargo test
```

## Code Style

- **rustfmt** — all code must be formatted with `cargo fmt`.
- **clippy** — all code must pass `cargo clippy -- -D warnings`.

Both checks are enforced by CI on every push and pull request.

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes and add tests if applicable.
3. Ensure all checks pass:
   ```bash
   cargo test
   cargo fmt --check
   cargo clippy -- -D warnings
   ```
4. Open a pull request against `main`.
5. A maintainer will review your PR. Please be patient and responsive to feedback.

## License

By contributing to this project, you agree that your contributions will be licensed under the [GNU General Public License v3.0](LICENSE.txt).
