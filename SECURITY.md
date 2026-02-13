# Security Policy

## Scope

This project is a CLI tool that downloads and compiles DNS blocklists into a binary format. It does **not** perform DNS filtering itself.

Security issues in scope include:

- Vulnerabilities in binary format parsing or serialization
- Unsafe handling of downloaded list content (e.g., path traversal, injection)
- Dependency vulnerabilities

Out of scope:

- Content accuracy of upstream blocklists (report these to the upstream maintainers)
- DNS filtering behavior (this tool only compiles lists)

## Reporting a Vulnerability

Please report security vulnerabilities through [GitHub Private Vulnerability Reporting](https://github.com/msquareau/dns-blocklist/security/advisories/new).

Do **not** open a public issue for security vulnerabilities.

## Response

We aim to acknowledge reports within 7 days and provide a fix or mitigation plan within 30 days.
