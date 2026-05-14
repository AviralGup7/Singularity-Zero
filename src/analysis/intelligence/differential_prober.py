"""
Cyber Security Test Pipeline - Differential Logic Prober
Implements multi-context response analysis for IDOR and BAC detection.
"""

from __future__ import annotations

from typing import Any

from diff_match_patch import diff_match_patch

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

class DifferentialLogicProber:
    """
    Frontier Logic Analyzer.
    Compares API responses across different user contexts to detect
    Authorization Bypass and Insecure Direct Object Reference (IDOR).
    """
    def __init__(self):
        self._dmp = diff_match_patch()

    def analyze_responses(self, base_response: str, compare_response: str) -> dict[str, Any]:
        """
        Compare two responses and calculate the logic-leakage score.
        """
        diffs = self._dmp.diff_main(base_response, compare_response)
        self._dmp.diff_cleanupSemantic(diffs)

        # Calculate percentage of similarity
        levenshtein = self._dmp.diff_levenshtein(diffs)
        max_len = max(len(base_response), len(compare_response), 1)
        similarity = 1.0 - (levenshtein / max_len)

        # Heuristic: If responses are > 95% similar but headers/auth differ,
        # it's likely a logic vulnerability.
        is_suspicious = similarity > 0.95 and levenshtein > 0

        return {
            "similarity": round(similarity, 4),
            "levenshtein_distance": levenshtein,
            "is_suspicious": is_suspicious,
            "diff_summary": self._summarize_diffs(diffs)
        }

    def _summarize_diffs(self, diffs: list[tuple[int, str]]) -> str:
        """Extract only the meaningful changes between responses."""
        changes = []
        for op, text in diffs:
            if op != 0: # 0 is equality
                changes.append(f"{'+' if op == 1 else '-'}{text[:50]}...")
        return " | ".join(changes[:5])

    def scan_for_idor(self, endpoint_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Perform a differential scan across a set of endpoint responses.
        Expects a list of (context_id, response_body) pairs.
        """
        findings = []
        for i in range(len(endpoint_data)):
            for j in range(i + 1, len(endpoint_data)):
                ctx_a = endpoint_data[i]
                ctx_b = endpoint_data[j]

                # Compare responses from different users for the same endpoint
                result = self.analyze_responses(ctx_a["body"], ctx_b["body"])

                if result["is_suspicious"]:
                    findings.append({
                        "type": "logic_breach:idor",
                        "title": "Potential IDOR Detected via Differential Analysis",
                        "confidence": result["similarity"],
                        "description": f"Responses from context '{ctx_a['id']}' and '{ctx_b['id']}' "
                                     f"are {result['similarity']*100}% identical despite different auth.",
                        "metadata": {
                            "levenshtein": result["levenshtein_distance"],
                            "diff": result["diff_summary"]
                        }
                    })
        return findings

def apply_differential_analysis(endpoint_responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Helper to trigger the frontier logic prober."""
    prober = DifferentialLogicProber()
    return prober.scan_for_idor(endpoint_responses)
