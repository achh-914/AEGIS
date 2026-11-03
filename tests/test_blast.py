import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.blast import blast_radius
from aegis.loader import build_graph

SNAP = os.path.join(os.path.dirname(__file__), "..", "examples", "aws_breach_demo.json")


def _graph():
    with open(SNAP, encoding="utf-8") as f:
        return build_graph(json.load(f))


def test_compromised_app_role_reaches_admin_and_data():
    reached = blast_radius(_graph(), "role:app-role")
    assert set(reached) == {"role:admin-role", "s3:customer-data"}


def test_leaf_resource_is_contained():
    assert blast_radius(_graph(), "s3:customer-data") == {}


def test_internet_reaches_whole_chain():
    reached = blast_radius(_graph(), "internet")
    assert len(reached) == 4
    assert len(reached["s3:customer-data"]) == 4


def test_start_node_never_in_result():
    assert "role:app-role" not in blast_radius(_graph(), "role:app-role")


if __name__ == "__main__":
    test_compromised_app_role_reaches_admin_and_data()
    test_leaf_resource_is_contained()
    test_internet_reaches_whole_chain()
    test_start_node_never_in_result()
    print("OK: 4 blast tests passed")
