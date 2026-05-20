"""
Cognitive-Logic: Flow-Aware State Machine Analysis.

Analyzes API interactions as stateful sequences, detecting business logic
vulnerabilities such as unauthenticated state transitions, step skipping,
and parameter-dependency tampering.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.passive.runtime import ResponseCache
from src.recon.ranking_support import build_flow_graph

logger = logging.getLogger(__name__)

# Parameters that likely track flow state
STATE_TOKEN_PATTERNS = [
    r"(?i)id$",
    r"(?i)uuid$",
    r"(?i)token$",
    r"(?i)session$",
    r"(?i)cart",
    r"(?i)order",
    r"(?i)step",
    r"(?i)state",
    r"(?i)transaction",
    r"(?i)payment",
]


class FlowProber:
    """
    Advanced State-Machine Analyzer for Business Logic.
    Identifies and tests multi-request sequences.
    """

    def __init__(self, response_cache: ResponseCache):
        self.cache = response_cache

    def analyze_flows(self, urls: set[str], limit: int = 15) -> list[dict[str, Any]]:
        """
        Main entry point for flow-aware analysis.
        """
        # 1. Discover flows using existing infrastructure
        flow_graph = build_flow_graph(list(urls))
        flows = flow_graph.get("flows", [])

        findings: list[dict[str, Any]] = []

        for flow in flows:
            if len(findings) >= limit:
                break

            chain = flow.get("chain", [])
            if len(chain) < 2:
                continue

            # 2. Extract State Tokens for this flow
            state_tokens = self._extract_flow_tokens(chain)

            # 3. Apply Multi-Step Probing Strategies
            flow_findings = self._probe_flow_integrity(flow, state_tokens)
            findings.extend(flow_findings)

        return findings[:limit]

    def _extract_flow_tokens(self, chain: list[str]) -> dict[str, set[str]]:
        """Identify parameters that appear across the chain."""
        tokens: dict[str, set[str]] = {}
        for url in chain:
            for name, value in meaningful_query_pairs(url):
                if any(re.search(p, name) for p in STATE_TOKEN_PATTERNS):
                    tokens.setdefault(name, set()).add(value)
        return tokens

    def _probe_flow_integrity(self, flow: dict[str, Any], tokens: dict[str, set[str]]) -> list[dict[str, Any]]:
        """Test the state machine for logical weaknesses."""
        findings = []
        chain = flow.get("chain", [])
        if len(chain) < 2:
            return []

        last_step = chain[-1]
        early_step = chain[0]

        try:
            # 1. Access last step with referer but NO state tokens from previous steps
            # Only run if we actually HAVE tokens to strip from the last step
            stripped_url = self._strip_tokens(last_step, tokens)

            if stripped_url != last_step:
                res = self.cache.request(
                    stripped_url,
                    headers={"Referer": early_step, "Cache-Control": "no-cache"}
                )

                if res and int(res.get("status_code", 0)) < 400:
                    findings.append({
                        "url": last_step,
                        "endpoint_key": endpoint_signature(last_step),
                        "category": "business_logic",
                        "title": "Unenforced State Transition",
                        "description": f"The terminal step of the '{flow.get('label')}' flow was reachable without required state tokens from earlier steps.",
                        "severity": "medium",
                        "evidence": {
                            "flow": flow.get("label"),
                            "terminal_step": last_step,
                            "status_code": res.get("status_code"),
                            "stripped_url": stripped_url
                        },
                        "signals": ["premature_step_access", "logic_bypass_candidate"]
                    })

            # Strategy B: Cross-Resource State Mapping (ID Traversal)
            # Find a 'step' or 'id' parameter and try to fuzz its value
            for param, values in tokens.items():
                if not values:
                    continue
                # Only fuzz if the parameter is actually in the last step
                if f"{param}=" not in last_step:
                    continue

                val = list(values)[0]
                fuzzed_val = self._generate_logical_mutation(val)
                if not fuzzed_val:
                    continue

                fuzzed_url = last_step.replace(f"{param}={val}", f"{param}={fuzzed_val}")
                f_res = self.cache.request(fuzzed_url, headers={"Cache-Control": "no-cache"})

                if f_res and int(f_res.get("status_code", 0)) < 300:
                    findings.append({
                        "url": last_step,
                        "endpoint_key": endpoint_signature(last_step),
                        "category": "business_logic",
                        "title": "Loose State-to-Session Binding",
                        "description": f"The state parameter '{param}' was successfully mutated, suggesting lack of server-side validation against the active session.",
                        "severity": "high",
                        "evidence": {
                            "parameter": param,
                            "original": val,
                            "mutated": fuzzed_val,
                            "status_code": f_res.get("status_code")
                        },
                        "signals": ["state_parameter_tampering", "idor_candidate"]
                    })

        except Exception as e:
            logger.debug("FlowProber: Integrity check failed for %s: %s", flow.get("host"), e)

        return findings

    def _strip_tokens(self, url: str, tokens: dict[str, set[str]]) -> str:
        """Remove state tokens from URL query parameters."""
        from urllib.parse import parse_qsl, urlencode, urlunparse
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        filtered = [(k, v) for k, v in query if k not in tokens]
        return urlunparse(parsed._replace(query=urlencode(filtered)))

    def _generate_logical_mutation(self, value: str) -> str | None:
        """Generate a logically different but syntactically valid ID."""
        if value.isdigit():
            # Try incrementing or decrementing
            return str(int(value) + 1)
        if len(value) == 36 and "-" in value: # UUID
            import uuid
            return str(uuid.uuid4())
        return None

def run_cognitive_flow_analysis(
    urls: set[str], response_cache: ResponseCache, limit: int = 12
) -> list[dict[str, Any]]:
    """Standalone entry point for flow analysis."""
    prober = FlowProber(response_cache)
    return prober.analyze_flows(urls, limit=limit)
