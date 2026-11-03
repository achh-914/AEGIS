from __future__ import annotations
from collections import deque


def blast_radius(graph, start):
    """Everything reachable from `start`, with the shortest path to each node.

    Answers: "if this identity or resource is compromised, what falls?"
    Returns {node_id: [Edge, ...]} and never includes `start` itself.
    """
    reached = {}
    queue = deque([(start, [])])
    seen = {start}
    while queue:
        cur, path = queue.popleft()
        for e in graph.neighbors(cur):
            if e.dst in seen:
                continue
            seen.add(e.dst)
            new_path = path + [e]
            reached[e.dst] = new_path
            queue.append((e.dst, new_path))
    return reached
