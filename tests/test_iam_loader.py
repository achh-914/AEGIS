import copy
import json
import os
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.blast import blast_radius
from aegis.loader import build_graph
from aegis.scan import scan

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def _data(name="aws_iam_authz_details.json"):
    with open(os.path.join(EX, name), encoding="utf-8") as f:
        return json.load(f)


def _edges(g):
    return {(e.src, e.dst): e for es in g.out.values() for e in es}


def test_nodes_are_built_from_the_export():
    g = build_graph(_data())
    assert set(g.nodes) == {
        "internet", "account:999988887777",
        "role:web-app-role", "role:deploy-admin", "role:legacy-ci",
        "role:partner-access", "role:guarded-role",
        "s3:customer-data", "s3:finance-reports", "s3:partner-exchange"}
    assert g.warnings == []


def test_admin_role_is_flagged():
    g = build_graph(_data())
    assert g.nodes["role:deploy-admin"].props["admin"] is True
    assert g.nodes["role:web-app-role"].props["admin"] is False


def test_trust_edges():
    e = _edges(build_graph(_data()))
    assert "any principal" in e[("internet", "role:legacy-ci")].reason
    assert "cross-account" in e[("account:999988887777", "role:partner-access")].reason
    assert ("internet", "role:web-app-role") not in e


def test_passrole_needs_permission_and_service_trust():
    e = _edges(build_graph(_data()))
    assert e[("role:web-app-role", "role:deploy-admin")].reason == "iam:PassRole + ec2:RunInstances"
    assert ("role:web-app-role", "role:legacy-ci") not in e
    assert ("role:partner-access", "role:deploy-admin") not in e


def test_explicit_deny_blocks_bucket_edge():
    e = _edges(build_graph(_data()))
    assert ("role:guarded-role", "s3:customer-data") in e
    assert ("role:guarded-role", "s3:finance-reports") not in e


def test_scan_from_internet_finds_open_trust():
    f = scan(build_graph(_data()), "internet")
    assert len(f) == 1
    assert f[0]["target"] == "s3:finance-reports" and f[0]["severity"] == "CRITICAL"
    assert f[0]["tags"] == ["OPEN-TRUST"]


def test_scan_from_external_account_finds_cross_account():
    f = scan(build_graph(_data()), "account:999988887777")
    assert len(f) == 1 and f[0]["target"] == "s3:partner-exchange"
    assert f[0]["severity"] == "MEDIUM" and f[0]["tags"] == ["CROSS-ACCOUNT-TRUST"]


def test_blast_radius_of_web_app_role():
    reached = blast_radius(build_graph(_data()), "role:web-app-role")
    assert "role:deploy-admin" in reached
    assert {"s3:customer-data", "s3:finance-reports", "s3:partner-exchange"} <= set(reached)


def test_missing_managed_policy_warns_instead_of_crashing():
    d = copy.deepcopy(_data())
    d["Policies"] = [p for p in d["Policies"] if p["PolicyName"] != "AppS3Access"]
    g = build_graph(d)
    assert any("AppS3Access" in w for w in g.warnings)
    assert ("role:web-app-role", "s3:customer-data") not in _edges(g)


def test_unreadable_policy_document_is_skipped_with_warning():
    d = copy.deepcopy(_data())
    d["RoleDetailList"][0]["RolePolicyList"][0]["PolicyDocument"] = "not json at all"
    g = build_graph(d)
    assert any("unreadable" in w for w in g.warnings)
    assert "role:web-app-role" in g.nodes


def test_url_encoded_trust_policy_is_decoded():
    d = copy.deepcopy(_data())
    for r in d["RoleDetailList"]:
        r["AssumeRolePolicyDocument"] = quote(json.dumps(r["AssumeRolePolicyDocument"]))
    e = _edges(build_graph(d))
    assert ("internet", "role:legacy-ci") in e


def test_demo_format_still_works():
    g = build_graph(_data("aws_breach_demo.json"))
    assert "ec2:web-01" in g.nodes
    assert len(scan(g)) == 1
