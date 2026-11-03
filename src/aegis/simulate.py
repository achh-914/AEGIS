from __future__ import annotations
import copy
from .loader import build_graph
from .paths import find_paths


def apply_change(data, remove_ingress=None):
    """Return a modified COPY of the snapshot. The original is never touched."""
    d = copy.deepcopy(data)
    if remove_ingress:
        sg_id, port = remove_ingress.rsplit(":", 1)
        for sg in d.get("security_groups", []):
            if sg["id"] == sg_id:
                sg["ingress"] = [r for r in sg.get("ingress", [])
                                 if str(r.get("port")) != str(port)]
    return d


def sensitive_targets(graph):
    return [n.id for n in graph.nodes.values()
            if n.type == "s3_bucket" and n.props.get("sensitive")]


def _collect(graph, source, targets):
    found = {}
    for t in targets:
        for path in find_paths(graph, source, t):
            found[" -> ".join([source] + [e.dst for e in path])] = path
    return found


def simulate(data, source="internet", targets=None, remove_ingress=None):
    before_g = build_graph(data)
    after_g = build_graph(apply_change(data, remove_ingress))
    targets = targets or sensitive_targets(before_g)
    before = _collect(before_g, source, targets)
    after = _collect(after_g, source, targets)
    return {
        "before": sorted(before),
        "after": sorted(after),
        "closed": sorted(set(before) - set(after)),
        "opened": sorted(set(after) - set(before)),
    }
