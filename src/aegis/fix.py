from __future__ import annotations
import copy
import re
from .loader import build_graph
from .scan import scan

# Lower number = safer / more targeted fix, tried first.
PRIORITY = {
    "PUBLIC-BUCKET": 0,
    "OPEN-INGRESS": 1,
    "OPEN-TRUST": 2,
    "PRIVESC-PASSROLE": 3,
    "LEAST-PRIVILEGE": 4,
}


def _key(finding):
    return " -> ".join(e.dst for e in finding["path"]) + "|" + finding["target"]


def _candidates(path):
    out = []
    for e in path:
        r = e.reason
        if "allows 0.0.0.0/0" in r:
            m = re.match(r"(\S+) allows 0\.0\.0\.0/0 on :(\S+)", r)
            if m:
                out.append({"rule": "OPEN-INGRESS", "action": "remove_ingress",
                            "sg": m.group(1), "port": m.group(2),
                            "desc": "remove 0.0.0.0/0 ingress on %s:%s" % (m.group(1), m.group(2))})
        elif "any principal" in r:
            name = e.dst.split(":", 1)[1]
            out.append({"rule": "OPEN-TRUST", "action": "restrict_trust", "role": name,
                        "desc": "restrict the trust policy of role %s to known principals" % name})
        elif "public access" in r:
            name = e.dst.split(":", 1)[1]
            out.append({"rule": "PUBLIC-BUCKET", "action": "block_public", "bucket": name,
                        "desc": "block public access on bucket %s" % name})
        elif "PassRole" in r:
            src = e.src.split(":", 1)[1]
            dst = e.dst.split(":", 1)[1]
            out.append({"rule": "PRIVESC-PASSROLE", "action": "remove_passrole",
                        "role": src, "target": dst,
                        "desc": "remove iam:PassRole from %s towards %s" % (src, dst)})
        elif r == "s3:*":
            role = e.src.split(":", 1)[1]
            bucket = e.dst.split(":", 1)[1]
            out.append({"rule": "LEAST-PRIVILEGE", "action": "revoke_s3",
                        "role": role, "bucket": bucket,
                        "desc": "revoke s3:* from %s on bucket %s" % (role, bucket)})
    return out


def apply_fix(data, c):
    """Return a modified COPY of the snapshot. The original is never touched."""
    d = copy.deepcopy(data)
    a = c["action"]
    if a == "remove_ingress":
        for sg in d.get("security_groups", []):
            if sg["id"] == c["sg"]:
                sg["ingress"] = [r for r in sg.get("ingress", [])
                                 if not (r.get("cidr") == "0.0.0.0/0"
                                         and str(r.get("port")) == str(c["port"]))]
    elif a == "restrict_trust":
        for r in d.get("roles", []):
            if r["name"] == c["role"]:
                r["trust_any_principal"] = False
    elif a == "block_public":
        for b in d.get("buckets", []):
            if b["name"] == c["bucket"]:
                b["public"] = False
    elif a == "remove_passrole":
        for r in d.get("roles", []):
            if r["name"] == c["role"]:
                r["can_pass_to"] = [t for t in r.get("can_pass_to", []) if t != c["target"]]
    elif a == "revoke_s3":
        for r in d.get("roles", []):
            if r["name"] == c["role"]:
                r["s3_full_access"] = [b for b in r.get("s3_full_access", []) if b != c["bucket"]]
    return d


def plan(data):
    """For every finding, pick the first fix that closes it and opens nothing new."""
    findings = scan(build_graph(data))
    before = {_key(f) for f in findings}
    items = []
    for f in findings:
        cands = sorted(_candidates(f["path"]), key=lambda c: PRIORITY[c["rule"]])
        chosen = None
        for c in cands:
            after = {_key(x) for x in scan(build_graph(apply_fix(data, c)))}
            if _key(f) not in after and not (after - before):
                chosen = c
                break
        items.append({"finding": f, "fix": chosen})
    return items


def apply_all(data, fixes):
    """Apply every fix to a copy and return the findings that remain."""
    d = copy.deepcopy(data)
    for c in fixes:
        d = apply_fix(d, c)
    return scan(build_graph(d))


def terraform(c):
    a = c["action"]
    if a == "block_public":
        b = c["bucket"]
        return ('resource "aws_s3_bucket_public_access_block" "%s" {\n'
                '  bucket                  = "%s"\n'
                '  block_public_acls       = true\n'
                '  block_public_policy     = true\n'
                '  ignore_public_acls      = true\n'
                '  restrict_public_buckets = true\n'
                '}' % (b, b))
    if a == "remove_ingress":
        return ('# aws_security_group "%s": delete the ingress rule that allows\n'
                '#   from_port = %s, cidr_blocks = ["0.0.0.0/0"]\n'
                '# and, if access is still needed, restrict it to a known range:\n'
                '#   cidr_blocks = [var.admin_cidr]' % (c["sg"], c["port"]))
    if a == "restrict_trust":
        return ('# aws_iam_role "%s": in assume_role_policy, replace\n'
                '#   Principal = "*"\n'
                '# with the specific account or service that must assume this role.' % c["role"])
    if a == "remove_passrole":
        return ('# aws_iam_role "%s": remove iam:PassRole from its policies, or limit\n'
                '#   Resource to the exact roles it must pass (not "%s").' % (c["role"], c["target"]))
    if a == "revoke_s3":
        return ('# aws_iam_role "%s": replace s3:* on bucket "%s" with the minimal\n'
                '#   read/write actions this role actually needs.' % (c["role"], c["bucket"]))
    return "# no template for this fix"
