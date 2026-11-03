from __future__ import annotations
from collections import defaultdict
from .model import Node, Edge


class Graph:
    """Directed graph: nodes are resources, edges are trust / reachability."""

    def __init__(self):
        self.nodes = {}
        self.out = defaultdict(list)

    def add_node(self, node: Node):
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge):
        self.out[edge.src].append(edge)

    def neighbors(self, node_id):
        return self.out.get(node_id, [])
