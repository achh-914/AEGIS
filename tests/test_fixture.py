import json
import os

FIX = os.path.join(os.path.dirname(__file__), "..", "examples", "aws_iam_authz_details.json")


def _load():
    with open(FIX, encoding="utf-8") as f:
        return json.load(f)


def test_fixture_has_real_api_shape():
    d = _load()
    for key in ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"):
        assert key in d


def test_fixture_roles_are_complete():
    roles = _load()["RoleDetailList"]
    assert {r["RoleName"] for r in roles} == {
        "web-app-role", "deploy-admin", "legacy-ci", "partner-access", "guarded-role"}
    for r in roles:
        for key in ("Arn", "AssumeRolePolicyDocument", "RolePolicyList", "AttachedManagedPolicies"):
            assert key in r


def test_fixture_is_synthetic():
    text = json.dumps(_load())
    assert "111122223333" in text and "999988887777" in text
