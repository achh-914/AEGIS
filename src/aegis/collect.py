"""Read-only collector for a real AWS account.

Calls exactly two APIs:
  * iam:GetAccountAuthorizationDetails  (needs IAMReadOnlyAccess or SecurityAudit)
  * sts:GetCallerIdentity               (needs no permission)

It never creates, changes or deletes anything. boto3 is an optional dependency:
    pip install -e ".[aws]"
"""
from __future__ import annotations
import json
import os
import subprocess

KEYS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")


class CollectError(Exception):
    pass


def make_clients(profile=None):
    try:
        import boto3
    except ImportError:
        raise CollectError('boto3 is not installed. Run: pip install boto3')
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("iam"), session.client("sts")


def identity(sts):
    ident = sts.get_caller_identity()
    return ident["Account"], ident["Arn"]


def fetch_authorization_details(iam):
    """Follow pagination and merge every page. Read-only."""
    merged = {k: [] for k in KEYS}
    marker = None
    while True:
        kwargs = {"Marker": marker} if marker else {}
        resp = iam.get_account_authorization_details(**kwargs)
        for k in KEYS:
            merged[k].extend(resp.get(k, []))
        if resp.get("IsTruncated") and resp.get("Marker"):
            marker = resp["Marker"]
        else:
            return merged


def _git_ignored(path):
    """True/False when inside a git repo, None when git cannot tell."""
    try:
        r = subprocess.run(["git", "check-ignore", "-q", path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    if r.returncode == 0:
        return True
    if r.returncode == 1:
        return False
    return None


def save_snapshot(data, path, force=False):
    """Write the export with owner-only permissions, refusing tracked locations."""
    if _git_ignored(path) is False and not force:
        raise CollectError(
            "refusing to write a real cloud export to %s: the path is not git-ignored. "
            "Use snapshots/ or pass --force." % path)
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    os.chmod(path, 0o600)
    return path


def summary(data):
    return {
        "roles": len(data.get("RoleDetailList", [])),
        "users": len(data.get("UserDetailList", [])),
        "groups": len(data.get("GroupDetailList", [])),
        "policies": len(data.get("Policies", [])),
    }
