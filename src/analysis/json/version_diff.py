"""Version diffing analysis for JSON responses.

Contains functions for comparing responses across different API versions
to detect behavioral differences, auth check variations, field exposure
changes, and error handling inconsistencies.
Extracted from json_analysis.py for better separation of concerns.
"""

from difflib import SequenceMatcher
from typing import Any

from src.analysis.helpers import endpoint_base_key, endpoint_signature
from src.analysis.json.support import (
    alternate_version_url as _alternate_version_url,
)
from src.analysis.passive.runtime import extract_key_fields, normalize_compare_text
from src.recon.common import normalize_url


def version_diffing(urls: set[str], response_cache: Any, limit: int = 20) -> list[dict[str, Any]]:
    """Compare responses across different API versions to detect behavioral differences."""
    findings: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, ...]] = set()
    url_set = {normalize_url(url) for url in urls if url}
    for url in sorted(url_set):
        counterpart = _alternate_version_url(url)
        if not counterpart:
            continue
        pair: tuple[str, ...] = tuple(sorted((url, counterpart)))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        original = response_cache.get(url)
        alternative = (
            response_cache.get(counterpart)
            if counterpart in url_set
            else response_cache.request(counterpart, headers={"Cache-Control": "no-cache"})
        )
        if not original or not alternative:
            continue
        similarity = round(
            SequenceMatcher(
                None,
                normalize_compare_text(original.get("body_text") or ""),
                normalize_compare_text(alternative.get("body_text") or ""),
            ).ratio(),
            3,
        )
        if original.get("status_code") == alternative.get("status_code") and similarity >= 0.98:
            continue
        findings.append(
            {
                "url": url,
                "comparison_url": counterpart,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "status_pair": [original.get("status_code"), alternative.get("status_code")],
                "body_similarity": similarity,
                "shared_key_fields": sorted(
                    extract_key_fields(original.get("body_text") or "")
                    & extract_key_fields(alternative.get("body_text") or "")
                )[:12],
            }
        )
        if len(findings) >= limit:
            break
    return findings
