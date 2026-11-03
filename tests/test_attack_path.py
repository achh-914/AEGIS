import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.loader import build_graph
from aegis.paths import find_paths

SNAP = os.path.join(os.path.dirname(__file__), "..", "examples", "aws_breach_demo.json")


def _data():
    with open(SNAP, encoding="utf-8") as f:
        return json.load(f)


def test_finds_internet_to_s3_path():
    paths = find_paths(build_graph(_data()), "internet", "s3:customer-data")
    assert len(paths) == 1
    assert [e.dst for e in paths[0]] == [
        "ec2:web-01", "role:app-role", "role:admin-role", "s3:customer-data"
    ]


def test_path_closed_after_fix():
    fixed = copy.deepcopy(_data())
    fixed["security_groups"][0]["ingress"] = []  # remove 0.0.0.0/0 on :22
    assert find_paths(build_graph(fixed), "internet", "s3:customer-data") == []


if __name__ == "__main__":
    test_finds_internet_to_s3_path()
    test_path_closed_after_fix()
    print("OK: 2 tests passed")
