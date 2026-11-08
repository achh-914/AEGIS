import datetime
import json
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis import collect
from aegis.collect import CollectError, fetch_authorization_details, save_snapshot, summary


class FakeIam:
    """Two pages, like the real API when the response is truncated."""

    def __init__(self):
        self.calls = []

    def get_account_authorization_details(self, **kwargs):
        self.calls.append(kwargs)
        if not kwargs:
            return {"RoleDetailList": [{"RoleName": "a"}], "Policies": [{"PolicyName": "p1"}],
                    "IsTruncated": True, "Marker": "next-page"}
        return {"RoleDetailList": [{"RoleName": "b"}], "UserDetailList": [{"UserName": "u"}],
                "IsTruncated": False}


def test_pagination_is_followed_and_merged():
    iam = FakeIam()
    data = fetch_authorization_details(iam)
    assert iam.calls == [{}, {"Marker": "next-page"}]
    assert [r["RoleName"] for r in data["RoleDetailList"]] == ["a", "b"]
    assert len(data["UserDetailList"]) == 1 and len(data["Policies"]) == 1
    assert data["GroupDetailList"] == []


def test_summary_counts():
    s = summary(fetch_authorization_details(FakeIam()))
    assert s == {"roles": 2, "users": 1, "groups": 0, "policies": 1}


def test_datetimes_are_serialized_and_file_is_private():
    data = {"RoleDetailList": [{"RoleName": "x", "CreateDate": datetime.datetime(2026, 1, 2, 3, 4, 5)}]}
    original = collect._git_ignored
    collect._git_ignored = lambda path: True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_snapshot(data, os.path.join(tmp, "snapshots", "iam.json"))
            assert json.load(open(path))["RoleDetailList"][0]["CreateDate"].startswith("2026-01-02")
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    finally:
        collect._git_ignored = original


def test_refuses_to_write_to_a_tracked_location():
    original = collect._git_ignored
    collect._git_ignored = lambda path: False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "iam.json")
            try:
                save_snapshot({}, target)
                assert False, "should have refused"
            except CollectError as e:
                assert "git-ignored" in str(e)
            assert not os.path.exists(target)
            save_snapshot({}, target, force=True)
            assert os.path.exists(target)
    finally:
        collect._git_ignored = original


def test_unknown_git_state_does_not_block():
    original = collect._git_ignored
    collect._git_ignored = lambda path: None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            assert save_snapshot({}, os.path.join(tmp, "iam.json"))
    finally:
        collect._git_ignored = original
