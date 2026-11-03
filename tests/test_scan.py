import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.loader import build_graph
from aegis.scan import scan

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def _data(name):
    with open(os.path.join(EX, name), encoding="utf-8") as f:
        return json.load(f)


def test_demo_has_one_critical_finding_with_rules():
    f = scan(build_graph(_data("aws_breach_demo.json")))
    assert len(f) == 1 and f[0]["severity"] == "CRITICAL"
    assert f[0]["tags"] == ["OPEN-INGRESS", "PRIVESC-PASSROLE"]


def test_multi_risk_counts_and_ranking():
    f = scan(build_graph(_data("aws_multi_risk.json")))
    assert [x["severity"] for x in f].count("CRITICAL") == 3
    assert len(f) == 4
    assert f[0]["target"] == "s3:public-backups" and f[0]["hops"] == 1


def test_internal_only_bucket_is_not_reported():
    f = scan(build_graph(_data("aws_multi_risk.json")))
    assert "s3:logs" not in [x["target"] for x in f]


def test_open_trust_rule_detected():
    f = scan(build_graph(_data("aws_multi_risk.json")))
    fin = [x for x in f if x["target"] == "s3:finance-reports"][0]
    assert fin["tags"] == ["OPEN-TRUST"] and fin["hops"] == 2


def test_fixing_public_bucket_removes_finding():
    d = copy.deepcopy(_data("aws_multi_risk.json"))
    for b in d["buckets"]:
        if b["name"] == "public-backups":
            b["public"] = False
    f = scan(build_graph(d))
    assert "s3:public-backups" not in [x["target"] for x in f]


if __name__ == "__main__":
    test_demo_has_one_critical_finding_with_rules()
    test_multi_risk_counts_and_ranking()
    test_internal_only_bucket_is_not_reported()
    test_open_trust_rule_detected()
    test_fixing_public_bucket_removes_finding()
    print("OK: 5 scan tests passed")
