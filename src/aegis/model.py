from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Node:
    id: str
    type: str
    name: str
    props: dict = field(default_factory=dict, hash=False, compare=False)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str
    reason: str = ""
