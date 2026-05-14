"""URL filter and parameter extraction helpers.

This module centralizes URL filtering and parameter-name extraction so
the logic can be tested and reused outside of `urls.collect_urls`.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    endpoint_signature,
    has_meaningful_parameters,
    meaningful_query_pairs,
)
from src.core.accelerators import vectorized_url_filter
from src.recon.common import normalize_url


def apply_url_filters(urls: set[str], filters: dict[str, Any] | None) -> set[str]:
    """Unified URL filtering with hardware-accelerated fast path for large datasets."""
    if not urls:
        return set()
        
    if filters is None:
        filters = {}
        
    ignored_exts = {item.lower().lstrip(".") for item in filters.get("ignore_extensions", [])}
    
    # --- Frontier Fast Path: Vectorized Hardware Acceleration ---
    # We trigger the accelerator if we have a significant volume of data (>1000 URLs)
    if len(urls) > 1000:
        url_list = list(urls)
        # 1. Hardware accelerated extension filtering
        fast_filtered = vectorized_url_filter(url_list, ignored_exts)
        # 2. Refine with meaningful parameter heuristics
        refined: set[str] = set()
        for url in fast_filtered:
            normalized = normalize_url(url)
            if normalized and ("?" not in normalized or has_meaningful_parameters(normalized)):
                refined.add(normalized)
        return refined

    # --- Standard Fallback: Low-latency loop for small sets ---
    filtered: set[str] = set()
    for url in urls:
        normalized = normalize_url(url)
        if not normalized:
            continue
        path = urlparse(normalized).path.lower()
        # Extension check
        ext = path.rsplit('.', 1)[-1] if '.' in path else ""
        if ext in ignored_exts:
            continue
        if "?" in normalized and not has_meaningful_parameters(normalized):
            continue
        filtered.add(normalized)
    return filtered


def extract_parameters(urls: list[str] | set[str]) -> set[str]:
    names: set[str] = set()
    for url in urls:
        for key, _ in meaningful_query_pairs(url):
            names.add(f"{key}=FUZZ")
    return names


def filter_similar(urls: set[str], max_results: int = 5000) -> set[str]:
    """Reduce a large URL set by collapsing similar endpoints.

    Heuristic:
    - Canonicalize URLs with `normalize_url`.
    - Deduplicate by `endpoint_signature` (path + meaningful param names).
    - Choose a deterministic representative per signature preferring
      URLs without query strings and shallower paths.
    - If the number of representatives exceeds `max_results`, keep the
      top-scoring representatives by the same preference heuristic.

    This is intentionally conservative and deterministic so results are
    reproducible across runs.
    """
    if not urls:
        return set()

    sig_map: dict[str, set[str]] = {}
    for raw in urls:
        normalized = normalize_url(raw)
        if not normalized:
            continue
        sig = endpoint_signature(normalized, include_host=True)
        sig_map.setdefault(sig, set()).add(normalized)

    # Pick a representative URL for each signature
    reps: list[str] = []
    for sig, candidates in sig_map.items():

        def _rep_key(u: str) -> tuple[int, int, int, str]:
            p = urlparse(u)
            has_query = 1 if p.query else 0
            depth = len([s for s in p.path.split("/") if s])
            return (has_query, depth, len(p.path), u)

        rep = min(candidates, key=_rep_key)
        reps.append(rep)

    # If already within budget, return all representatives
    if len(reps) <= max_results:
        return set(reps)

    # Otherwise sort by preference and trim
    def _sort_key(u: str) -> tuple[int, int, str]:
        p = urlparse(u)
        return (0 if not p.query else 1, len([s for s in p.path.split("/") if s]), u)

    reps_sorted = sorted(reps, key=_sort_key)
    return set(reps_sorted[:max_results])


__all__ = ["apply_url_filters", "extract_parameters"]
