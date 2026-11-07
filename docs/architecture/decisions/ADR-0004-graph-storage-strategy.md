# ADR-0004: Graph storage strategy

- Status: Accepted for in-memory; persistent storage Proposed
- Date: 2026-11-07

## Context
Analysis runs on snapshots of one account at a time, so graphs are
small enough to fit in memory.

## Decision
Build the graph in memory from a JSON snapshot on every run. No
database is used. Simulations work on a copy of the graph.

## Consequences
- No infrastructure to run; results are reproducible from a snapshot.
- Large multi-account graphs and history are not supported yet.
- A graph database can be evaluated if scale or history is needed.
