# ADR-0006: Evidence-first AI

- Status: Proposed (no AI features implemented)
- Date: 2026-11-07

## Context
AI could help explain findings and draft fixes, but unsupported
claims are dangerous in a security tool.

## Decision
If AI is added, it may only explain or propose based on evidence the
graph already contains (paths, nodes, edges). Its output must cite
that evidence and must never change findings by itself.

## Consequences
- The deterministic engine stays the source of truth.
- AI features are optional and can be turned off.
- Nothing in the current code depends on a model.
