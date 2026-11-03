# Contributing to AEGIS

Thanks for your interest in AEGIS! The project is in early development, and contributions of all sizes are welcome.

## Ways to contribute

- Report bugs or suggest features through GitHub Issues.
- Improve documentation and examples.
- Add resource types, graph edges, or detection rules.
- Write tests, especially reference attack paths.

## Getting started

    git clone https://github.com/achh-914/AEGIS.git
    cd AEGIS
    python3 -m venv .venv
    source .venv/bin/activate

## Workflow

1. Fork the repository and create a branch: `git checkout -b feat/my-change`
2. Make small, focused commits with clear messages (`feat:`, `fix:`, `docs:`, `test:`).
3. Add or update tests for your change.
4. Open a pull request describing what changed and why.

## Guidelines

- AEGIS is **read-only by design**. Never add code that modifies cloud resources.
- **Never commit** real credentials, account IDs, or customer snapshots. Use anonymized sample data only.
- Keep the graph schema and rules documented.

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).

By contributing, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
