import json
import os
import sys
from urllib.parse import quote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.policy import (ALLOW, DENY, IMPLICIT_DENY, can, evaluate, is_admin,
                          parse_document, statements)

FIX = os.path.join(os.path.dirname(__file__), "..", "examples", "aws_iam_authz_details.json")


def doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def allow(action, resource="*", **extra):
    s = {"Effect": "Allow", "Action": action, "Resource": resource}
    s.update(extra)
    return s


def deny(action, resource="*", **extra):
    s = {"Effect": "Deny", "Action": action, "Resource": resource}
    s.update(extra)
    return s


def test_exact_and_wildcard_actions():
    d = [doc(allow("s3:GetObject"))]
    assert evaluate(d, "s3:GetObject") == ALLOW
    assert evaluate(d, "s3:PutObject") == IMPLICIT_DENY
    assert can([doc(allow("s3:*"))], "s3:DeleteBucket")
    assert can([doc(allow("iam:Pass*"))], "iam:PassRole")
    assert not can([doc(allow("iam:Pass*"))], "iam:CreateUser")


def test_actions_are_case_insensitive():
    assert can([doc(allow("S3:GETOBJECT"))], "s3:getobject")


def test_resource_matching():
    d = [doc(allow("s3:GetObject", "arn:aws:s3:::data/*"))]
    assert can(d, "s3:GetObject", "arn:aws:s3:::data/file.txt")
    assert not can(d, "s3:GetObject", "arn:aws:s3:::other/file.txt")


def test_explicit_deny_wins_over_allow():
    d = [doc(allow("s3:*"), deny("s3:*", "arn:aws:s3:::secret/*"))]
    assert evaluate(d, "s3:GetObject", "arn:aws:s3:::secret/x") == DENY
    assert evaluate(d, "s3:GetObject", "arn:aws:s3:::open/x") == ALLOW


def test_deny_wins_across_documents():
    docs = [doc(allow("*")), doc(deny("iam:*"))]
    assert evaluate(docs, "iam:CreateUser") == DENY
    assert evaluate(docs, "s3:GetObject") == ALLOW


def test_implicit_deny_when_nothing_matches():
    assert evaluate([], "s3:GetObject") == IMPLICIT_DENY
    assert evaluate([doc(allow("ec2:*"))], "s3:GetObject") == IMPLICIT_DENY


def test_condition_handling_is_conservative():
    cond = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    assert can([doc(allow("s3:*", Condition=cond))], "s3:GetObject")
    assert evaluate([doc(allow("s3:*"), deny("s3:*", Condition=cond))], "s3:GetObject") == ALLOW


def test_notaction():
    d = [doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})]
    assert can(d, "s3:GetObject")
    assert not can(d, "iam:CreateUser")


def test_single_statement_object_and_string_forms():
    d = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}}
    assert can([d], "s3:GetObject")
    assert len(statements(d)) == 1


def test_parse_json_string_and_url_encoded():
    raw = json.dumps(doc(allow("s3:*")))
    assert parse_document(raw)["Statement"]
    assert parse_document(quote(raw))["Statement"]
    assert can([quote(raw)], "s3:GetObject")


def test_is_admin():
    assert is_admin([doc(allow("*"))])
    assert not is_admin([doc(allow("s3:*"))])
    assert not is_admin([doc(allow("*"), deny("iam:*"))])


def test_fixture_policies_behave_as_designed():
    with open(FIX, encoding="utf-8") as f:
        data = json.load(f)
    roles = {r["RoleName"]: r for r in data["RoleDetailList"]}
    guarded = [p["PolicyDocument"] for p in roles["guarded-role"]["RolePolicyList"]]
    assert can(guarded, "s3:GetObject", "arn:aws:s3:::logs/a")
    assert evaluate(guarded, "s3:GetObject", "arn:aws:s3:::finance-reports/q3.csv") == DENY
    admin = [v["Document"] for p in data["Policies"] if p["PolicyName"] == "AdministratorAccess"
             for v in p["PolicyVersionList"]]
    assert is_admin(admin)
