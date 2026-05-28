"""Exploit Chain Drift & Jaccard Similarity Graph Engine.

Computes changes, Jaccard similarity metrics, and structural changes
between findings across execution runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ChainDiffEngine:
    """Computes differences and Jaccard similarity metrics between scan runs."""

    @staticmethod
    def get_findings_keys(findings_file: Path) -> set[str]:
        """Extract a unique hash key signature for every finding."""
        if not findings_file.exists():
            return set()
        try:
            content = findings_file.read_text(encoding="utf-8")
            data = json.loads(content)
            findings = data.get("findings", []) if isinstance(data, dict) else data
            keys = set()
            for f in findings:
                if isinstance(f, dict):
                    # Combine endpoint and category/type to form a unique vector key
                    endpoint = f.get("url", f.get("endpoint", "unknown"))
                    category = f.get("category", f.get("type", "unknown"))
                    keys.add(f"{category}:{endpoint}")
            return keys
        except Exception:
            return set()

    @classmethod
    def diff_runs(cls, run_a_dir: str | Path, run_b_dir: str | Path) -> dict[str, Any]:
        """Compute the difference metrics and identify drift between two runs."""
        path_a = Path(run_a_dir) / "findings.json"
        path_b = Path(run_b_dir) / "findings.json"

        keys_a = cls.get_findings_keys(path_a)
        keys_b = cls.get_findings_keys(path_b)

        if not keys_a and not keys_b:
            return {
                "similarity": 1.0,
                "drift_detected": False,
                "new_exposures": [],
                "remediated_paths": [],
            }

        intersection = keys_a.intersection(keys_b)
        union = keys_a.union(keys_b)

        similarity = len(intersection) / len(union) if union else 0.0
        new_exposures = list(keys_b - keys_a)
        remediated_paths = list(keys_a - keys_b)

        return {
            "similarity": round(similarity, 4),
            "drift_detected": similarity < 0.95,
            "new_exposures": new_exposures,
            "remediated_paths": remediated_paths,
            "metrics": {
                "run_a_total": len(keys_a),
                "run_b_total": len(keys_b),
                "common_count": len(intersection),
            },
        }
