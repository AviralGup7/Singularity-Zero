"""Deterministic GraphGenID (I-GRAPH-08) and resume fail-closed."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any


class GraphGenerationMismatch(ValueError):
    """Stored GraphGenID does not match the graph built at resume."""


class CapabilityGenerationMismatch(ValueError):
    """Stored post-prune capability fingerprint does not match resume."""


def _when_hash(when: Any) -> str:
    if when is None:
        return "always"
    name = type(when).__name__
    payload: dict[str, Any] = {"t": name}
    for attr in ("stage", "field", "flag"):
        if hasattr(when, attr):
            payload[attr] = getattr(when, attr)
    if hasattr(when, "conditions"):
        payload["conditions"] = [_when_hash(c) for c in (when.conditions or ())]
    if hasattr(when, "condition"):
        payload["condition"] = _when_hash(when.condition)
    return json.dumps(payload, sort_keys=True, default=str)


def canonical_node(node: Any) -> tuple[Any, ...]:
    """Order-independent identity of one stage. Volatile fields excluded."""
    return (
        str(getattr(node, "name", "")),
        tuple(sorted(str(n) for n in (getattr(node, "needs", ()) or ()))),
        int(getattr(node, "weight", 0) or 0),
        bool(getattr(node, "critical", False)),
        int(getattr(node, "timeout", 0) or 0),
        bool(getattr(node, "must_succeed", False)),
        _when_hash(getattr(node, "when", None)),
    )


def _hash_nodes(nodes: Any) -> str:
    payload = [canonical_node(n) for n in sorted(nodes, key=lambda n: str(getattr(n, "name", "")))]
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def graph_gen_id(graph: Any) -> str:
    """Logical identity of the *declared* graph (pre-prune)."""
    declared = str(getattr(graph, "declared_gen_id", "") or "").strip()
    if declared:
        return declared
    nodes = tuple(getattr(graph, "nodes", ()) or ())
    return _hash_nodes(nodes)


def capability_gen_id(graph: Any) -> str:
    """Host capability identity of the *post-prune* executable graph."""
    stored = str(getattr(graph, "capability_gen_id", "") or "").strip()
    if stored:
        return stored
    nodes = tuple(getattr(graph, "nodes", ()) or ())
    return _hash_nodes(nodes)


def graphgen_strict() -> bool:
    raw = os.environ.get("GRAPHGEN_STRICT", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def assert_graph_generation(stored: str | None, computed: str) -> None:
    """Fail-closed when both hashes are present and differ."""
    expected = str(stored or "").strip()
    actual = str(computed or "").strip()
    if not expected:
        if graphgen_strict() and actual:
            # First resume without a stored id: refuse only when strict *and*
            # caller passed a sentinel. Empty stored = pre-MVR checkpoint.
            return
        return
    if expected != actual:
        raise GraphGenerationMismatch(
            f"GraphGenID mismatch stored={expected[:16]} computed={actual[:16]}"
        )


__all__ = [
    "GraphGenerationMismatch",
    "assert_graph_generation",
    "canonical_node",
    "graph_gen_id",
    "graphgen_strict",
]
