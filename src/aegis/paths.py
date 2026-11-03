from __future__ import annotations


def find_paths(graph, source, target, max_depth=8):
    """Return every simple path (list of edges) from source to target."""
    results = []

    def dfs(cur, path, seen):
        if cur == target:
            results.append(list(path))
            return
        if len(path) >= max_depth:
            return
        for e in graph.neighbors(cur):
            if e.dst in seen:
                continue
            path.append(e)
            seen.add(e.dst)
            dfs(e.dst, path, seen)
            path.pop()
            seen.remove(e.dst)

    dfs(source, [], {source})
    return results
