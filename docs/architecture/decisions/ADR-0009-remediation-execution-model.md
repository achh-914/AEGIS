# ADR-0009: Remediation execution model

- Status: Accepted (verification planned)
- Date: 2026-11-07

## Context
Automatically changing a production cloud is risky and can break
services.

## Decision
AEGIS never modifies the cloud. `aegis fix` generates Terraform or
manual patch snippets that a human reviews and applies. Changes can
first be tested with `aegis simulate` on a copy of the graph.

## Consequences
- Safe by default; the user stays in control.
- A standalone `verify` command (before/after snapshot diff) is on
  the roadmap and not implemented yet.
