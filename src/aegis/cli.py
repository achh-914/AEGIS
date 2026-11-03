from __future__ import annotations
import argparse
from .loader import load_snapshot
from .paths import find_paths

RED, GRN, DIM, BLD, RST = "\033[91m", "\033[92m", "\033[2m", "\033[1m", "\033[0m"


def main(argv=None):
    p = argparse.ArgumentParser(prog="aegis")
    sub = p.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("paths", help="find attack paths")
    pp.add_argument("--snapshot", required=True)
    pp.add_argument("--from", dest="src", default="internet")
    pp.add_argument("--to", dest="dst", required=True)
    a = p.parse_args(argv)

    g = load_snapshot(a.snapshot)
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
