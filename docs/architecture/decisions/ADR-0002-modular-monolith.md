# ADR-0002: Modular monolith

- Status: Accepted
- Date: 2026-11-07

## Context
The project is small and developed by one person. Separate services
would add deployment and debugging cost without benefit.

## Decision
Ship one Python package (`src/aegis`) with clear modules: loaders,
graph, rules/scan, simulate, fix and the CLI.

## Consequences
- Simple install (`pip install -e .`) and fast tests.
- Modules can be split into services later if a REST API is added.
- Module boundaries must be kept by discipline, not by the runtime.
