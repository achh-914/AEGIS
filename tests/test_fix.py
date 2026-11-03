import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.fix import apply_all, plan, terraform

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def _data(name="aws_multi_risk.json"):
    with open(os.path.join(EX, name), encoding="utf-8") as f:
        return json.load(f)


def _fixes(items):
    out, seen = [], set()
    for it in items:
        k = json.dumps(it["fix"], sort_keys=True)
        if it["fix"] and k not in seen:
            seen.add(k)
            out.append(it["fix"])
    return out


def test_every_finding_has_a_fix():
    items = plan(_data())
    assert len(items) == 4
    assert all(it["fix"] is not None for it in items)


def test_chosen_rules():
    by_target = {it["finding"]["target"]: it["fix"]["rule"] for it in plan(_data())}
    assert by_target["s3:public-backups"] == "PUBLIC-BUCKET"
    assert by_target["s3:customer-data"] == "OPEN-INGRESS"
    assert by_target["s3:finance-reports"] == "OPEN-TRUST"


def test_applying_all_fixes_leaves_nothing():
    d = _data()
    assert apply_all(d, _fixes(plan(d))) == []


def test_original_snapshot_untouched():
    d = _data()
    before = copy.deepcopy(d)
    apply_all(d, _fixes(plan(d)))
    assert d == before


def test_terraform_snippet():
    fixes = _fixes(plan(_data()))
    snippets = "\n".join(terraform(c) for c in fixes)
    assert "aws_s3_bucket_public_access_block" in snippets
    assert "0.0.0.0/0" in snippets


if __name__ == "__main__":
    test_every_finding_has_a_fix()
    test_chosen_rules()
    test_applying_all_fixes_leaves_nothing()
    test_original_snapshot_untouched()
    test_terraform_snippet()
    print("OK: 5 fix tests passed")
