"""Build an AEGIS graph from `aws iam get-account-authorization-details` output.

Scope (documented limits):
  * Roles, their trust policies, inline and managed policies are analysed.
  * Users and groups are parsed by the export but not modelled yet.
  * S3 buckets are discovered from policy Resource ARNs only (the export has
    no S3 data), and a bucket is flagged sensitive from its name (SENSITIVE_HINTS).
  * Conditions are ignored for reachability (over-approximation, on purpose).
"""
from __future__ import annotations
import re
from .graph import Graph
from .model import Node, Edge
from .policy import action_matches, can, is_admin, parse_document, statements

SENSITIVE_HINTS = ("customer", "finance", "payroll", "pii", "secret",
                   "credential", "backup", "private", "prod", "hr-")
S3_PREFIX = "arn:aws:s3:::"
ACCOUNT_RE = re.compile(r"^(?:arn:aws:iam::)?(\d{12})(?::.*)?$")
ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/")
PASSROLE_SERVICES = (
    ("ec2.amazonaws.com", "ec2:RunInstances"),
    ("lambda.amazonaws.com", "lambda:CreateFunction"),
)


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _safe(doc, label, warnings):
    try:
        parsed = parse_document(doc)
        statements(parsed)
        return parsed
    except Exception as exc:
        warnings.append("%s: unreadable policy document skipped (%s)" % (label, exc))
        return None


def _managed_index(data, warnings):
    index = {}
    for p in data.get("Policies", []):
        versions = p.get("PolicyVersionList", [])
        raw = None
        for v in versions:
            if v.get("IsDefaultVersion"):
                raw = v.get("Document")
                break
        if raw is None and versions:
            raw = versions[0].get("Document")
        if raw is None:
            continue
        doc = _safe(raw, "managed policy %s" % p.get("PolicyName"), warnings)
        if doc is not None:
            index[p.get("Arn")] = doc
    return index


def _role_docs(role, index, warnings):
    name = role.get("RoleName")
    docs = []
    for p in role.get("RolePolicyList", []):
        d = _safe(p.get("PolicyDocument"), "role %s inline policy %s" % (name, p.get("PolicyName")), warnings)
        if d is not None:
            docs.append(d)
    for ap in role.get("AttachedManagedPolicies", []):
        d = index.get(ap.get("PolicyArn"))
        if d is None:
            warnings.append("role %s: managed policy %s not found in export" % (name, ap.get("PolicyName")))
        else:
            docs.append(d)
    return docs


def _trust_statements(role, warnings):
    doc = _safe(role.get("AssumeRolePolicyDocument"), "role %s trust policy" % role.get("RoleName"), warnings)
    if doc is None:
        return []
    out = []
    for s in statements(doc):
        if s.get("Effect") != "Allow":
            continue
        if not any(action_matches(a, "sts:AssumeRole") for a in _as_list(s.get("Action"))):
            continue
        out.append(s)
    return out


def _principals(stmt):
    p = stmt.get("Principal")
    if p == "*":
        return [("AWS", "*")]
    if isinstance(p, dict):
        return [(k, v) for k, vals in p.items() for v in _as_list(vals)]
    return []


def _trusts_service(trust, service):
    return any(k == "Service" and v == service for s in trust for k, v in _principals(s))


def _trusts_principal(trust, role_arn, account):
    root = "arn:aws:iam::%s:root" % account if account else None
    for s in trust:
        for k, v in _principals(s):
            if k == "AWS" and v in ("*", role_arn, root):
                return True
    return False


def _buckets(all_docs):
    names = set()
    for docs in all_docs:
        for d in docs:
            for s in statements(d):
                for r in _as_list(s.get("Resource")):
                    if isinstance(r, str) and r.startswith(S3_PREFIX):
                        name = r[len(S3_PREFIX):].split("/")[0]
                        if name and "*" not in name and "?" not in name:
                            names.add(name)
    return sorted(names)


def build_iam_graph(data):
    warnings = []
    g = Graph()
    g.warnings = warnings
    g.add_node(Node("internet", "internet", "Internet"))

    roles = data.get("RoleDetailList", [])
    index = _managed_index(data, warnings)

    own = None
    for r in roles:
        m = ROLE_ARN_RE.match(r.get("Arn", ""))
        if m:
            own = m.group(1)
            break

    docs = {}
    trust = {}
    arn = {}
    for r in roles:
        name = r["RoleName"]
        docs[name] = _role_docs(r, index, warnings)
        trust[name] = _trust_statements(r, warnings)
        arn[name] = r.get("Arn")
        g.add_node(Node("role:" + name, "iam_role", name, {"admin": is_admin(docs[name])}))

    buckets = _buckets(docs.values())
    for b in buckets:
        g.add_node(Node("s3:" + b, "s3_bucket", b,
                        {"sensitive": any(h in b.lower() for h in SENSITIVE_HINTS)}))

    seen = set()

    def add(src, dst, kind, reason):
        if (src, dst) in seen or src == dst:
            return
        seen.add((src, dst))
        g.add_edge(Edge(src, dst, kind, reason))

    for name in docs:
        rid = "role:" + name
        # 1) who can assume this role from outside
        for s in trust[name]:
            cond = " [conditional]" if "Condition" in s else ""
            for k, v in _principals(s):
                if k != "AWS":
                    continue
                if v == "*":
                    add("internet", rid, "can_assume",
                        "trust policy allows any principal (*)" + cond)
                    continue
                m = ACCOUNT_RE.match(v)
                if m and m.group(1) != own:
                    acct = m.group(1)
                    g.add_node(Node("account:" + acct, "external_account", acct))
                    add("account:" + acct, rid, "can_assume",
                        "trust policy allows cross-account principal %s%s" % (v, cond))

    for a in docs:
        aid = "role:" + a
        for b in docs:
            if a == b:
                continue
            bid = "role:" + b
            # 2) iam:PassRole escalation
            if can(docs[a], "iam:PassRole", arn[b]):
                for service, action in PASSROLE_SERVICES:
                    if can(docs[a], action, "*") and _trusts_service(trust[b], service):
                        add(aid, bid, "can_assume", "iam:PassRole + %s" % action)
                        break
            # 3) direct sts:AssumeRole chain (both policies must allow)
            if can(docs[a], "sts:AssumeRole", arn[b]) and _trusts_principal(trust[b], arn[a], own):
                add(aid, bid, "can_assume", "sts:AssumeRole (permitted by both policies)")

    # 4) bucket access, with explicit Deny honoured
    for a in docs:
        for b in buckets:
            obj = S3_PREFIX + b + "/*"
            if can(docs[a], "s3:*", obj):
                add("role:" + a, "s3:" + b, "can_access", "s3:*")
            elif can(docs[a], "s3:GetObject", obj):
                add("role:" + a, "s3:" + b, "can_access", "s3:GetObject")
    return g
