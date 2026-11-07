# ADR-0001: Multi-cloud strategy

- Status: Accepted (AWS only today; other clouds planned)
- Date: 2026-11-07

## Context
AEGIS aims to analyze several clouds with one engine. Building all
providers at once would produce shallow support everywhere.

## Decision
Build one cloud deeply first (AWS), and map every provider into the
same canonical model (see ADR-0003). Azure and GCP are adapters that
only need to produce that model.

## Consequences
- The analysis engine stays cloud-agnostic.
- Only AWS input formats are supported today.
- Azure and GCP adapters are on the roadmap, not implemented.
