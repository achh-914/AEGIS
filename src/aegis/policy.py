"""Minimal, dependency-free IAM policy evaluation.

Rules implemented (same order as AWS):
  1. An explicit Deny always wins.
  2. Otherwise an Allow grants access.
  3. Otherwise the request is an implicit deny.

Conservative choices for a security tool (documented, tested):
  * An Allow that has a Condition still counts as allowed (over-approximate risk).
  * A Deny that has a Condition does NOT count as a deny (it may not apply).
"""
from __future__ import annotations
import fnmatch
import json
from urllib.parse import unquote

ALLOW = "Allow"
DENY = "Deny"
IMPLICIT_DENY = "ImplicitDeny"


def parse_document(doc):
    """Accept a dict, a JSON string, or a URL-encoded JSON string (raw IAM API)."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        text = doc.strip()
        if not text.startswith("{"):
            text = unquote(text)
        return json.loads(text)
    raise ValueError("unsupported policy document type: %s" % type(doc).__name__)


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(doc):
    """Return the list of statement dicts of a policy document."""
    return [s for s in _as_list(parse_document(doc).get("Statement")) if isinstance(s, dict)]


def action_matches(pattern, action):
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def resource_matches(pattern, resource):
    return fnmatch.fnmatchcase(resource, pattern)


def _statement_applies(stmt, action, resource):
    if "Action" in stmt:
        if not any(action_matches(p, action) for p in _as_list(stmt["Action"])):
            return False
    elif "NotAction" in stmt:
        if any(action_matches(p, action) for p in _as_list(stmt["NotAction"])):
            return False
    else:
        return False

    if "Resource" in stmt:
        return any(resource_matches(p, resource) for p in _as_list(stmt["Resource"]))
    if "NotResource" in stmt:
        return not any(resource_matches(p, resource) for p in _as_list(stmt["NotResource"]))
    return True


def evaluate(documents, action, resource="*"):
    """Evaluate `action` on `resource` against a list of policy documents."""
    allowed = False
    for doc in documents:
        for stmt in statements(doc):
            if not _statement_applies(stmt, action, resource):
                continue
            effect = stmt.get("Effect")
            if effect == DENY and "Condition" not in stmt:
                return DENY
            if effect == ALLOW:
                allowed = True
    return ALLOW if allowed else IMPLICIT_DENY


def can(documents, action, resource="*"):
    return evaluate(documents, action, resource) == ALLOW


_ADMIN_PROBES = [
    "iam:CreateAccessKey", "iam:PassRole", "iam:PutRolePolicy",
    "s3:GetObject", "ec2:RunInstances", "sts:AssumeRole",
]


def is_admin(documents):
    """True when the documents effectively grant full administrative access."""
    return all(can(documents, a, "*") for a in _ADMIN_PROBES)
