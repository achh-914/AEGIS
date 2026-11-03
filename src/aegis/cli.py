from __future__ import annotations
import argparse
import json
from .loader import build_graph
from .paths import find_paths
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

    a = p.parse_args(argv)
    return a.func(a)
