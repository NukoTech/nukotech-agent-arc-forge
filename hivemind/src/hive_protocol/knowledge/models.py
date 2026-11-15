"""Small immutable projection objects for the derived knowledge graph."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GraphNode:
    document: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "document", copy.deepcopy(self.document))

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.document)


@dataclass(frozen=True)
class GraphEdge:
    document: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "document", copy.deepcopy(self.document))

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.document)
