# ADR-0007: Cloud credential management

- Status: Accepted
- Date: 2026-11-07

## Context
Security tools that hold cloud credentials become a target and are
harder to adopt.

## Decision
AEGIS is offline-first. It analyzes JSON snapshots (for example the
output of `aws iam get-account-authorization-details`) and needs no
credentials. Collecting a snapshot is done separately with the
user's own tools.

## Consequences
- Nothing sensitive is stored or transmitted by AEGIS.
- Real exports contain account data and are git-ignored.
- Automatic collection is out of scope for now.
