"""Cryptographic Merkle Tree & Proof of Exploit Evidence for Zero-Trust Reporting."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def _hash_leaf(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(b"\x00" + data).hexdigest()


def _hash_node(left_hex: str, right_hex: str) -> str:
    combined = bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    return hashlib.sha256(b"\x01" + combined).hexdigest()


@dataclass(frozen=True, slots=True)
class MerkleProof:
    """Audit proof verifying leaf inclusion in a Merkle tree."""

    leaf_hash: str
    audit_path: tuple[tuple[str, str], ...]  # tuple of (hash, 'L' | 'R')
    root_hash: str

    def verify(self) -> bool:
        """Independently verify cryptographic inclusion in the root hash."""
        current = self.leaf_hash
        for sibling_hash, direction in self.audit_path:
            if direction == "L":
                current = _hash_node(sibling_hash, current)
            else:
                current = _hash_node(current, sibling_hash)
        return current == self.root_hash


class MerkleTree:
    """Builds a cryptographic SHA-256 Merkle Tree over raw finding evidence."""

    def __init__(self, raw_leaves: list[str | dict[str, Any]]) -> None:
        self._raw_leaves = raw_leaves
        self._leaves: list[str] = [
            _hash_leaf(json.dumps(leaf, sort_keys=True) if isinstance(leaf, dict) else str(leaf))
            for leaf in raw_leaves
        ]
        self._layers: list[list[str]] = []
        if self._leaves:
            self._build_tree()

    def _build_tree(self) -> None:
        current_layer = list(self._leaves)
        self._layers.append(current_layer)

        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                next_layer.append(_hash_node(left, right))
            current_layer = next_layer
            self._layers.append(current_layer)

    @property
    def root(self) -> str:
        if not self._layers or not self._layers[-1]:
            return hashlib.sha256(b"empty_tree").hexdigest()
        return self._layers[-1][0]

    def generate_proof(self, leaf_index: int) -> MerkleProof:
        """Generate an audit path for leaf at index."""
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise IndexError("Leaf index out of bounds")

        audit_path: list[tuple[str, str]] = []
        idx = leaf_index

        for layer in self._layers[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1 if idx + 1 < len(layer) else idx
                direction = "R"
            else:
                sibling_idx = idx - 1
                direction = "L"
            audit_path.append((layer[sibling_idx], direction))
            idx //= 2

        return MerkleProof(
            leaf_hash=self._leaves[leaf_index],
            audit_path=tuple(audit_path),
            root_hash=self.root,
        )


__all__ = [
    "MerkleProof",
    "MerkleTree",
]
