"""
Abstract Syntax Tree (AST) Grammar-Guided Mutator.
Implements syntactic boundary mutations for structured payloads (JSON/XML).
"""

from __future__ import annotations

import copy
import json
import random
from abc import ABC, abstractmethod
from typing import Any

class BaseASTMutator(ABC):
    """Abstract base class for all AST-based mutators."""

    @abstractmethod
    def mutate(self, base_text: str) -> list[str]:
        """Generate syntactic mutations of the input base string."""
        pass


class JSONASTMutator(BaseASTMutator):
    """Mutates JSON payloads by traversing their AST and applying syntactic transformations."""

    def __init__(self, strategies: list[Any] | None = None):
        super().__init__()
        self.strategies = strategies if strategies is not None else [
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
            mutated_ast = strategy(copy.deepcopy(ast))  # Work on a fresh copy
            results.append(json.dumps(mutated_ast, separators=(",", ":")))
        
        return results

    def _mutate_values(self, node: Any) -> Any:
        """Replace primitive values with boundary/injection values."""
        if isinstance(node, dict):
            new_dict = {}
            for k in node:
                new_dict[k] = self._mutate_values(node[k])
            return new_dict
        elif isinstance(node, list):
            new_list = []
            for item in node:
                new_list.append(self._mutate_values(item))
            return new_list
        elif isinstance(node, str):
            return random.choice(["' OR '1'='1", "<script>alert(1)</script>", "null"])
        elif isinstance(node, (int, float)):
            return random.choice([0, -1, 2147483647])
        return node

    def _swap_keys(self, node: Any) -> Any:
        """Swap keys within a dictionary to test schema flexibility."""
        if isinstance(node, dict) and len(node) >= 2:
            new_node = copy.deepcopy(node)
            keys = list(new_node.keys())
            k1, k2 = random.sample(keys, 2)
            new_node[k1], new_node[k2] = new_node[k2], new_node[k1]
            return new_node
        return node

    def _nest_deeply(self, node: Any) -> Any:
        """Recursively nest a value to test parser stack limits."""
        if isinstance(node, dict) and node:
            new_node = copy.deepcopy(node)
            key = random.choice(list(new_node.keys()))
            val = new_node[key]
            for _ in range(20):
                val = {"n": val}
            new_node[key] = val
            return new_node
        return node

    def _type_confusion(self, node: Any) -> Any:
        """Change the type of a node (e.g. string to list)."""
        if isinstance(node, dict) and node:
            new_node = copy.deepcopy(node)
            key = random.choice(list(new_node.keys()))
            new_node[key] = [new_node[key], "type_confusion_probe"]
            return new_node
        return node
