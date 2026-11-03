# Security Policy

AEGIS is a security tool, so we take vulnerabilities in the project itself seriously.

## Supported versions

The project is in early development. Only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue.**

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability** to open a private advisory.
3. Include a description, steps to reproduce, and the potential impact.

## What to expect

- Acknowledgement within a few days.
- An assessment and a fix plan once the report is confirmed.
- Credit in the release notes if you wish.

## Scope

In scope: vulnerabilities in AEGIS code, parsing of snapshots, report generation, and generated remediation patches.

Out of scope: weaknesses in third-party cloud providers or in infrastructure you analyze with AEGIS.

## Handling sensitive data

Cloud snapshots can contain sensitive information. Never share real snapshots or credentials in issues or pull requests; anonymize them first.
