import json
import logging
import secrets
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check
from src.fuzzing.diff_utils import compute_diff_ratio, find_byte_level_diffs, normalize_response

logger = logging.getLogger(__name__)


class GoldenResponseStore:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.baselines: dict[str, dict[str, Any]] = {}

    def capture(
        self,
        endpoint_key: str,
        body: str,
        status_code: int = 200,
        headers: dict | None = None,
        elapsed_ms: float = 0.0,
    ) -> None:
        normalized = normalize_response(body)
        self.store[endpoint_key] = normalized
        self.baselines[endpoint_key] = {
            "body": body,
            "status_code": status_code,
            "headers": headers or {},
            "elapsed_ms": elapsed_ms,
            "normalized": normalized,
        }

    def get(self, endpoint_key: str) -> str | None:
        return self.store.get(endpoint_key)

    def get_baseline(self, endpoint_key: str) -> dict[str, Any] | None:
        return self.baselines.get(endpoint_key)

    def has(self, endpoint_key: str) -> bool:
        return endpoint_key in self.store


_DIFF_THRESHOLD = 0.15
_TIMING_DIFF_THRESHOLD = 2.0  # seconds - threshold for timing differential


def _structural_diff(base_body: str, candidate_body: str) -> dict[str, Any]:
    """Compare two JSON responses structurally (new fields, missing fields, type changes)."""
    try:
        base_json = json.loads(base_body)
        cand_json = json.loads(candidate_body)
    except (ValueError, TypeError):
        return {"has_structural_diff": False, "details": []}

    if not isinstance(base_json, dict) or not isinstance(cand_json, dict):
        return {"has_structural_diff": False, "details": []}

    details = []
    base_keys = set(base_json.keys())
    cand_keys = set(cand_json.keys())

    new_keys = cand_keys - base_keys
    missing_keys = base_keys - cand_keys
    common_keys = base_keys & cand_keys

    if new_keys:
        details.append({"type": "new_fields", "fields": list(new_keys)})
    if missing_keys:
        details.append({"type": "missing_fields", "fields": list(missing_keys)})

    type_changes = []
    for key in common_keys:
        base_type = type(base_json[key]).__name__
        cand_type = type(cand_json[key]).__name__
        if base_type != cand_type:
            type_changes.append({"field": key, "from": base_type, "to": cand_type})
    if type_changes:
        details.append({"type": "type_changes", "changes": type_changes})

    return {
        "has_structural_diff": bool(details),
        "details": details,
    }


def _timing_differential(base_elapsed_ms: float, candidate_elapsed_ms: float) -> dict[str, Any]:
    """Detect timing differentials that may indicate timing side-channels."""
    delta = abs(candidate_elapsed_ms - base_elapsed_ms)
    # Use a more realistic threshold: 500ms for network jitter, 2000ms for real anomaly
    is_significant = delta > 500.0 and delta > (_TIMING_DIFF_THRESHOLD * 1000 * 0.5)
    return {
        "delta_ms": round(delta, 2),
        "is_significant": is_significant,
        "base_ms": round(base_elapsed_ms, 2),
        "candidate_ms": round(candidate_elapsed_ms, 2),
    }


async def _run_differential_probe(
    url: str,
    golden: GoldenResponseStore,
    *,
    client: httpx.AsyncClient,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    endpoint_key = endpoint_signature(url)
    endpoint_base = endpoint_base_key(url)
    endpoint_type = classify_endpoint(url)

    if not is_safe_url_with_dns_check(url):
        logger.warning("Differential fuzzer: URL failed safety check, skipping: %s", url)
        return findings

    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not query_pairs:
        return findings

    try:
        base_start = time.monotonic()
        base_resp = await client.get(url, timeout=timeout_seconds)
        base_elapsed = (time.monotonic() - base_start) * 1000
        base_status = base_resp.status_code
    except Exception as e:
        logger.warning("Differential fuzzer base request failed for %s: %s", url, e)
        return findings

    baseline_body = base_resp.text
    normalized_baseline = normalize_response(baseline_body)
    golden.capture(
        endpoint_key, normalized_baseline, base_status, dict(base_resp.headers), base_elapsed
    )

    mutations: list[tuple[str, str]] = []
    for idx, (param_name, param_value) in enumerate(query_pairs):
        bit_flipped = bytearray(param_value.encode("utf-8", errors="ignore"))
        if len(bit_flipped) > 0:
            bit_index = secrets.randbelow(len(bit_flipped))
            bit_flipped[bit_index] ^= 1 << secrets.randbelow(8)
            mutated_value = bit_flipped.decode("utf-8", errors="ignore")
        else:
            mutated_value = "A"
        mutations.append((param_name, mutated_value))

    count = min(10, len(query_pairs))
    for mutation_num in range(count):
        idx = mutation_num % len(query_pairs)
        param_name, _ = query_pairs[idx]
        mutated_pairs = list(query_pairs)
        if mutation_num < len(mutations):
            mutated_pairs[idx] = (param_name, mutations[mutation_num][1])
        else:
            mutated_pairs[idx] = (param_name, "0")
        mutated_query = urlencode(mutated_pairs, doseq=True)
        mutated_url = urlunparse(parsed._replace(query=mutated_query))

        if not is_safe_url_with_dns_check(mutated_url):
            continue

        try:
            cand_start = time.monotonic()
            resp = await client.get(mutated_url, timeout=timeout_seconds)
            cand_elapsed = (time.monotonic() - cand_start) * 1000
            status = resp.status_code
            body = resp.text
        except Exception as e:
            logger.debug("Differential fuzzer request failed for %s: %s", mutated_url, e)
            continue

        normalized_candidate = normalize_response(body)
        diff_ratio = compute_diff_ratio(normalized_baseline, normalized_candidate)

        if diff_ratio > _DIFF_THRESHOLD:
            diffs = find_byte_level_diffs(
                normalized_baseline, normalized_candidate, context_bytes=32
            )
            top_diffs = diffs[:3]

            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base,
                    "endpoint_type": endpoint_type,
                    "issues": ["differential_response_divergence"],
                    "probe_type": "differential_fuzzer",
                    "severity": "high",
                    "confidence": min(0.9, diff_ratio),
                    "evidence": {
                        "ratio": diff_ratio,
                        "diffs": top_diffs,
                        "url": mutated_url,
                        "payload": mutated_pairs[idx][1],
                        "status_code": status,
                        "parameter": param_name,
                        "strategy": "bit_flip",
                    },
                }
            )
            logger.info(
                "Differential fuzzer: divergence detected on %s (ratio=%.2f)", url, diff_ratio
            )

        # Structural diff: compare JSON field presence, absence, and type changes
        struct_diff = _structural_diff(baseline_body, body)
        if struct_diff["has_structural_diff"]:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base,
                    "endpoint_type": endpoint_type,
                    "issues": ["differential_structural_change"],
                    "probe_type": "differential_fuzzer",
                    "severity": "medium",
                    "confidence": 0.75,
                    "evidence": {
                        "structural_diff": struct_diff,
                        "url": mutated_url,
                        "parameter": param_name,
                        "payload": mutated_pairs[idx][1],
                    },
                }
            )
            logger.info("Differential fuzzer: structural change on %s", url)

        # Timing differential: detect response time changes that may indicate
        # timing side-channels (e.g., blind SQL injection with time-based payloads).
        timing = _timing_differential(base_elapsed, cand_elapsed)
        if timing["is_significant"]:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base,
                    "endpoint_type": endpoint_type,
                    "issues": ["differential_timing_anomaly"],
                    "probe_type": "differential_fuzzer",
                    "severity": "medium",
                    "confidence": 0.7,
                    "evidence": {
                        "timing": timing,
                        "url": mutated_url,
                        "parameter": param_name,
                        "payload": mutated_pairs[idx][1],
                    },
                }
            )
            logger.info(
                "Differential fuzzer: timing anomaly on %s (delta=%.1fms)", url, timing["delta_ms"]
            )

        if status >= 500 and base_status < 500:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base,
                    "endpoint_type": endpoint_type,
                    "issues": ["differential_crash_triggered"],
                    "probe_type": "differential_fuzzer",
                    "severity": "medium",
                    "confidence": 0.8,
                    "evidence": {
                        "base_status_code": base_status,
                        "status_code": status,
                        "url": mutated_url,
                        "parameter": param_name,
                        "payload": mutated_pairs[idx][1],
                        "strategy": "bit_flip",
                    },
                }
            )
            logger.info("Differential fuzzer: crash triggered on %s", url)

    return findings


async def run_differential_fuzzing_campaign(
    url: str,
    client: httpx.AsyncClient | None = None,
    *,
    timeout_seconds: float = 5.0,
    max_mutations: int = 10,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    golden = GoldenResponseStore()
    close_client = False

    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
        close_client = True

    try:
        probe_findings = await _run_differential_probe(
            url,
            golden,
            client=client,
            timeout_seconds=timeout_seconds,
        )
        findings.extend(probe_findings)
    finally:
        if close_client:
            await client.aclose()

    return findings
