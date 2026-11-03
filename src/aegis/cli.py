from __future__ import annotations
import argparse
import json
from .blast import blast_radius
from .fix import apply_all, plan, terraform
from .loader import build_graph
from .paths import find_paths
from .scan import scan
from .simulate import simulate

RED, GRN, YEL, DIM, BLD, RST = (
    "\033[91m", "\033[92m", "\033[93m", "\033[2m", "\033[1m", "\033[0m")


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cmd_paths(a):
    g = build_graph(_load(a.snapshot))
    edges = sum(len(v) for v in g.out.values())
    print("%s+ loaded %d resources, %d relationships%s" % (GRN, len(g.nodes), edges, RST))
    found = find_paths(g, a.src, a.dst)
    if not found:
        print("%s+ no attack path from %s to %s%s" % (GRN, a.src, a.dst, RST))
        return 0
    for n, path in enumerate(found, 1):
        print("\n%s%sCRITICAL%s attack path #%d (%d hops)" % (BLD, RED, RST, n, len(path)))
        print("  " + a.src)
        for e in path:
            print("  %s-> %s%s  %s[%s: %s]%s" % (RED, e.dst, RST, DIM, e.kind, e.reason, RST))
    return 0


def cmd_simulate(a):
    targets = [a.dst] if a.dst else None
    r = simulate(_load(a.snapshot), a.src, targets, a.remove_ingress)
    print("%s~ change:%s remove ingress %s" % (YEL, RST, a.remove_ingress))
    print("  before: %d attack path(s)" % len(r["before"]))
    print("  after : %d attack path(s)" % len(r["after"]))
    print("\n%s+ Paths closed: %d%s" % (GRN, len(r["closed"]), RST))
    for p in r["closed"]:
        print("  %s- %s%s" % (DIM, p, RST))
    col = RED if r["opened"] else GRN
    print("%s+ Paths opened: %d%s" % (col, len(r["opened"]), RST))
    for p in r["opened"]:
        print("  %s+ %s%s" % (RED, p, RST))
    return 1 if r["opened"] else 0


def cmd_blast(a):
    g = build_graph(_load(a.snapshot))
    if a.src not in g.nodes:
        print("%sx unknown node: %s%s" % (RED, a.src, RST))
        print("  available: " + ", ".join(sorted(g.nodes)))
        return 2
    reached = blast_radius(g, a.src)
    sensitive = [n for n in reached if g.nodes[n].props.get("sensitive")]
    print("%s~ blast radius of%s %s" % (YEL, RST, a.src))
    if not reached:
        print("%s+ nothing reachable: compromise stays contained%s" % (GRN, RST))
        return 0
    print("  %d resource(s) reachable, %d sensitive\n" % (len(reached), len(sensitive)))
    for nid, path in sorted(reached.items(), key=lambda kv: len(kv[1])):
        node = g.nodes[nid]
        flag = "  %s%s[SENSITIVE]%s" % (BLD, RED, RST) if node.props.get("sensitive") else ""
        print("  %s%-28s%s %s%-12s hops=%d%s%s" % (
            RED if flag else YEL, nid, RST, DIM, node.type, len(path), RST, flag))
    return 1 if sensitive else 0


def cmd_scan(a):
    g = build_graph(_load(a.snapshot))
    edges = sum(len(v) for v in g.out.values())
    print("%s+ loaded %d resources, %d relationships%s" % (GRN, len(g.nodes), edges, RST))
    findings = scan(g, a.src)
    if not findings:
        print("%s+ no exposed buckets found from %s%s" % (GRN, a.src, RST))
        return 0
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    for n, f in enumerate(findings, 1):
        col = RED if f["severity"] == "CRITICAL" else YEL
        print("\n%s%s%s%s #%d  %s  (%d hop%s)" % (
            BLD, col, f["severity"], RST, n, f["target"], f["hops"], "" if f["hops"] == 1 else "s"))
        print("  %srules: %s%s" % (DIM, ", ".join(f["tags"]) or "-", RST))
        print("  " + a.src)
        for e in f["path"]:
            print("  %s-> %s%s  %s[%s]%s" % (col, e.dst, RST, DIM, e.reason, RST))
    print("\n%s%d finding(s): %d critical, %d medium%s" % (
        BLD, len(findings), crit, len(findings) - crit, RST))
    return 1 if crit else 0


def cmd_fix(a):
    data = _load(a.snapshot)
    items = plan(data)
    if not items:
        print("%s+ nothing to fix: no exposed paths%s" % (GRN, RST))
        return 0
    fixes, seen = [], set()
    for n, it in enumerate(items, 1):
        f, c = it["finding"], it["fix"]
        col = RED if f["severity"] == "CRITICAL" else YEL
        print()
        print("%s%s%s%s #%d  %s  (%d hop%s)" % (
            BLD, col, f["severity"], RST, n, f["target"], f["hops"], "" if f["hops"] == 1 else "s"))
        if c is None:
            print("  %sno safe automatic fix found, review manually%s" % (RED, RST))
            continue
        print("  rule    : %s" % c["rule"])
        print("  fix     : %s" % c["desc"])
        print("  %sverified: path closed, 0 new paths opened%s" % (GRN, RST))
        k = json.dumps(c, sort_keys=True)
        if k not in seen:
            seen.add(k)
            fixes.append(c)
    remaining = apply_all(data, fixes)
    print()
    print("%s%d fix(es) planned: findings %d -> %d%s" % (BLD, len(fixes), len(items), len(remaining), RST))
    if a.terraform and fixes:
        print()
        print("# --- Terraform / manual patch (review before applying) ---")
        for c in fixes:
            print(terraform(c))
            print()
    print("%sAEGIS never applies changes. Review and apply the patch yourself.%s" % (DIM, RST))
    return 1 if remaining else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="aegis")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("paths", help="find attack paths")
    pp.add_argument("--snapshot", required=True)
    pp.add_argument("--from", dest="src", default="internet")
    pp.add_argument("--to", dest="dst", required=True)
    pp.set_defaults(func=cmd_paths)

    ps = sub.add_parser("simulate", help="what-if on a copy of the graph")
    ps.add_argument("--snapshot", required=True)
    ps.add_argument("--from", dest="src", default="internet")
    ps.add_argument("--to", dest="dst", default=None)
    ps.add_argument("--remove-ingress", required=True, metavar="SG:PORT")
    ps.set_defaults(func=cmd_simulate)

    pb = sub.add_parser("blast", help="what is reachable if this node is compromised")
    pb.add_argument("--snapshot", required=True)
    pb.add_argument("--from", dest="src", required=True)
    pb.set_defaults(func=cmd_blast)

    pc = sub.add_parser("scan", help="find every exposed path to every bucket")
    pc.add_argument("--snapshot", required=True)
    pc.add_argument("--from", dest="src", default="internet")
    pc.set_defaults(func=cmd_scan)

    pf = sub.add_parser("fix", help="plan verified fixes (never applies them)")
    pf.add_argument("--snapshot", required=True)
    pf.add_argument("--terraform", action="store_true", help="also print the patch")
    pf.set_defaults(func=cmd_fix)

    a = p.parse_args(argv)
    return a.func(a)
