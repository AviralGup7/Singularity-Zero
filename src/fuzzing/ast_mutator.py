"""
Abstract Syntax Tree (AST) Grammar-Guided Mutator.
Implements syntactic boundary mutations for structured payloads (JSON/XML).
"""

from __future__ import annotations

import json
import random
from typing import Any

class JSONASTMutator:
    """Mutates JSON payloads by traversing their AST and applying syntactic transformations."""

    def __init__(self):
        self.strategies = [
            self._mutate_values,
            self._swap_keys,
            self._nest_deeply,
            self._type_confusion,
        ]

    def mutate(self, base_json: str) -> list[str]:
        """Generate syntactic mutations of the input JSON string."""
        try:
            ast = json.loads(base_json)
        except json.JSONDecodeError:
            return []

        results = []
        for strategy in self.strategies:
            mutated_ast = strategy(json.loads(base_json)) # Work on a fresh copy
            results.append(json.dumps(mutated_ast, separators=(",", ":")))
        
        return results

    def _mutate_values(self, node: Any) -> Any:
        """Replace primitive values with boundary/injection values."""
        if isinstance(node, dict):
            for k in node:
                node[k] = self._mutate_values(node[k])
        elif isinstance(node, list):
            for i in range(len(node)):
                node[i] = self._mutate_values(node[i])
        elif isinstance(node, str):
            return random.choice(["' OR '1'='1", "<script>alert(1)</script>", "null"])
        elif isinstance(node, (int, float)):
            return random.choice([0, -1, 2147483647])
        return node

    def _swap_keys(self, node: Any) -> Any:
        """Swap keys within a dictionary to test schema flexibility."""
        if isinstance(node, dict) and len(node) >= 2:
            keys = list(node.keys())
            k1, k2 = random.sample(keys, 2)
            node[k1], node[k2] = node[k2], node[k1]
        return node

    def _nest_deeply(self, node: Any) -> Any:
        """Recursively nest a value to test parser stack limits."""
        if isinstance(node, dict) and node:
            key = random.choice(list(node.keys()))
            val = node[key]
            for _ in range(20):
                val = {"n": val}
            node[key] = val
        return node

    def _type_confusion(self, node: Any) -> Any:
        """Change the type of a node (e.g. string to list)."""
        if isinstance(node, dict) and node:
            key = random.choice(list(node.keys()))
            node[key] = [node[key], "type_confusion_probe"]
        return node
