# ADR-0008: Tenant isolation

- Status: Proposed (not implemented)
- Date: 2026-11-07

## Context
A hosted or multi-user version would need to keep customers' data
separate. Today AEGIS is a single-user command-line tool.

## Decision
Defer. If a REST API or dashboard is built, each tenant gets its own
graph and storage namespace, with no shared in-memory state.

## Consequences
- No isolation guarantees exist today because there is one user.
- This must be designed before any multi-tenant deployment.
