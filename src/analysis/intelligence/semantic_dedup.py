"""
Cyber Security Test Pipeline - Semantic Intelligence Engine
Implements high-speed vector-space finding deduplication using NumPy.
"""

from __future__ import annotations

import logging
import re
from typing import Any
import numpy as np

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

class SemanticDeduplicator:
    """
    Frontier Deduplication Engine.
    Uses Cosine Similarity in a vector space to detect functionally identical findings
    across different URLs or modules, even if descriptions slightly differ.
    """
    def __init__(self, threshold: float = 0.85):
        self._threshold = threshold
        self._vocabulary: dict[str, int] = {}
        self._next_id = 0

    def _tokenize(self, text: str) -> list[str]:
        """Normalize and tokenize finding titles/descriptions."""
        # Remove dynamic parts like IDs, timestamps, and hashes
        text = re.sub(r"[0-9a-f]{8,}", "[HASH]", text.lower())
        text = re.sub(r"\d+", "[NUM]", text)
        return re.findall(r"\w+", text)

    def _vectorize(self, tokens: list[str]) -> np.ndarray:
        """Create a frequency vector for the given tokens."""
        vec = np.zeros(max(len(self._vocabulary) + 100, 1000))
        for token in tokens:
            if token not in self._vocabulary:
                self._vocabulary[token] = self._next_id
                self._next_id += 1
            
            idx = self._vocabulary[token]
            if idx < len(vec):
                vec[idx] += 1
        return vec

    def compute_similarity(self, vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return np.dot(vec_a, vec_b) / (norm_a * norm_b)

    def deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Filter a list of findings, keeping only semantically unique entries.
        Complexity: O(N^2) but optimized via NumPy.
        """
        if not findings:
            return []

        unique_findings = []
        vectors = []

        for finding in findings:
            text = f"{finding.get('title', '')} {finding.get('description', '')}"
            tokens = self._tokenize(text)
            vec = self._vectorize(tokens)
            
            is_duplicate = False
            for existing_vec in vectors:
                # Truncate vectors to same size for comparison
                size = min(len(vec), len(existing_vec))
                sim = self.compute_similarity(vec[:size], existing_vec[:size])
                
                if sim > self._threshold:
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                unique_findings.append(finding)
                vectors.append(vec)

        logger.info("Semantic Dedup: Reduced %d findings to %d unique signals", 
                    len(findings), len(unique_findings))
        return unique_findings

def apply_frontier_deduplication(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Helper to apply the highest-tier deduplication logic."""
    engine = SemanticDeduplicator()
    return engine.deduplicate(findings)
