# ADR-0003: Canonical domain model

- Status: Accepted
- Date: 2026-11-07

## Context
Each cloud describes resources differently. Rules and path analysis
should not depend on provider-specific formats.

## Decision
Represent infrastructure as a graph. Nodes are resources (for example
IAM roles, S3 buckets, external accounts, the internet). Edges are
relationships such as `can_reach` and `can_assume`, each carrying a
human-readable reason.

## Consequences
- Attack paths, blast radius and simulation work on one structure.
- Every finding can show the edges that justify it.
- New providers must be translated into this model.
