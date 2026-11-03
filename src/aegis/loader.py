from __future__ import annotations
import json
from .graph import Graph
from .model import Node, Edge


def load_snapshot(path):
    with open(path, encoding="utf-8") as f:
        return build_graph(json.load(f))


def build_graph(data):
    g = Graph()
    g.add_node(Node("internet", "internet", "Internet"))

    open_sgs = {}
    for sg in data.get("security_groups", []):
        for rule in sg.get("ingress", []):
            if rule.get("cidr") == "0.0.0.0/0":
                open_sgs[sg["id"]] = "%s allows 0.0.0.0/0 on :%s" % (sg["id"], rule.get("port"))

    for r in data.get("roles", []):
        g.add_node(Node("role:" + r["name"], "iam_role", r["name"]))
        if r.get("trust_any_principal"):
            g.add_edge(Edge("internet", "role:" + r["name"], "can_assume",
                            "trust policy allows any principal (*)"))

    for b in data.get("buckets", []):
        bid = "s3:" + b["name"]
        g.add_node(Node(bid, "s3_bucket", b["name"], {"sensitive": b.get("sensitive", False)}))
        if b.get("public"):
            g.add_edge(Edge("internet", bid, "can_access", "bucket policy allows public access"))

    for i in data.get("instances", []):
        nid = "ec2:" + i["name"]
        g.add_node(Node(nid, "ec2_instance", i["name"]))
        for sgid in i.get("security_groups", []):
            if sgid in open_sgs:
                g.add_edge(Edge("internet", nid, "can_reach", open_sgs[sgid]))
        if i.get("role"):
            g.add_edge(Edge(nid, "role:" + i["role"], "can_assume", "instance profile"))

    for r in data.get("roles", []):
        rid = "role:" + r["name"]
        for target in r.get("can_pass_to", []):
            g.add_edge(Edge(rid, "role:" + target, "can_assume", "iam:PassRole + ec2:RunInstances"))
        for bucket in r.get("s3_full_access", []):
            g.add_edge(Edge(rid, "s3:" + bucket, "can_access", "s3:*"))
    return g
