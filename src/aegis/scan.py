from __future__ import annotations
from .paths import find_paths

RULES = [
    ("OPEN-INGRESS", "0.0.0.0/0"),
    ("PRIVESC-PASSROLE", "PassRole"),
    ("OPEN-TRUST", "any principal"),
    ("PUBLIC-BUCKET", "public access"),
    ("CROSS-ACCOUNT-TRUST", "cross-account"),
    ("ASSUME-CHAIN", "sts:AssumeRole"),
]


def tags_for(path):
    reasons = " | ".join(e.reason for e in path)
    return [rule for rule, needle in RULES if needle in reasons]


def scan(graph, source="internet"):
    """Find every path from `source` to every S3 bucket, ranked by severity."""
    findings = []
    for node in graph.nodes.values():
        if node.type != "s3_bucket":
            continue
        for path in find_paths(graph, source, node.id):
            findings.append({
                "target": node.id,
                "severity": "CRITICAL" if node.props.get("sensitive") else "MEDIUM",
                "hops": len(path),
                "tags": tags_for(path),
                "path": path,
            })
    findings.sort(key=lambda f: (0 if f["severity"] == "CRITICAL" else 1, f["hops"], f["target"]))
    return findings
