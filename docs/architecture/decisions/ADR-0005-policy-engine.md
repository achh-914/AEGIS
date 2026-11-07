# ADR-0005: Policy engine

- Status: Accepted
- Date: 2026-11-07

## Context
Risk in AWS depends on how IAM policies combine. Checking for
wildcards alone gives false positives and false negatives.

## Decision
Evaluate IAM policies with Allow/Deny semantics, wildcard matching
and `NotAction`, so an explicit Deny overrides an Allow. Detection
rules (for example OPEN-TRUST, CROSS-ACCOUNT-TRUST, PRIVESC-PASSROLE)
run on top of the resulting graph.

## Consequences
- More accurate access edges than keyword matching.
- Condition keys and permission boundaries are not fully modeled yet.
- Each rule needs a positive and a negative test.
