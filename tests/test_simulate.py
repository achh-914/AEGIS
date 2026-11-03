import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.simulate import simulate

SNAP = os.path.join(os.path.dirname(__file__), "..", "examples", "aws_breach_demo.json")


def _data():
    with open(SNAP, encoding="utf-8") as f:
        return json.load(f)


def test_removing_ssh_closes_path():
    r = simulate(_data(), "internet", None, "sg-0a1b:22")
    assert len(r["before"]) == 1 and r["after"] == []
    assert len(r["closed"]) == 1 and r["opened"] == []


def test_unrelated_change_closes_nothing():
    r = simulate(_data(), "internet", None, "sg-0a1b:443")
    assert r["closed"] == [] and len(r["after"]) == 1


if __name__ == "__main__":
    test_removing_ssh_closes_path()
    test_unrelated_change_closes_nothing()
    print("OK: 2 simulate tests passed")
