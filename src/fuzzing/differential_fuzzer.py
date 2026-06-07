import asyncio
import hashlib
import logging
from typing import Any

import httpx
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check
from src.fuzzing.diff_utils import normalize_response, compute_diff_ratio, find_byte_level_diffs, strip_dynamic_headers

logger = logging.getLogger(__name__)


class GoldenResponseStore:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def capture(self, endpoint_key: str, body: str) -> None:
        normalized = normalize_response(body)
        self.store[endpoint_key] = normalized

    def get(self, endpoint_key: str) -> str | None:
        return self.store.get(endpoint_key)

    def has(self, endpoint_key: str) -> bool:
        return endpoint_key in self.store


_DIFF_THRESHOLD = 0.15


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
        base_resp = await client.get(url, timeout=timeout_seconds)
        base_status = base_resp.status_code
    except Exception as e:
        logger.warning("Differential fuzzer base request failed for %s: %s", url, e)
        return findings

    baseline_body = base_resp.text
    normalized_baseline = normalize_response(baseline_body)
    golden.capture(endpoint_key, normalized_baseline)

    mutations: list[tuple[str, str]] = []
    for idx, (param_name, param_value) in enumerate(query_pairs):
        bit_flipped = bytearray(param_value.encode('utf-8', errors='ignore'))
        if len(bit_flipped) > 0:
            bit_index = (hash(url + param_name) + idx) % len(bit_flipped)
            bit_flipped[bit_index] ^= 1 << ((bit_index + idx) % 8)
            mutated_value = bit_flipped.decode('utf-8', errors='ignore')
        else:
            mutated_value = 'A'
        mutations.append((param_name, mutated_value))

    count = min(10, len(query_pairs))
    for mutation_num in range(count):
        idx = mutation_num % len(query_pairs)
        param_name, _ = query_pairs[idx]
        mutated_pairs = list(query_pairs)
        if mutation_num < len(mutations):
            mutated_pairs[idx] = (param_name, mutations[mutation_num][1])
        else:
            mutated_pairs[idx] = (param_name, '0')
        mutated_query = urlencode(mutated_pairs, doseq=True)
        mutated_url = urlunparse(parsed._replace(query=mutated_query))

        if not is_safe_url_with_dns_check(mutated_url):
            continue

        try:
            resp = await client.get(mutated_url, timeout=timeout_seconds)
            status = resp.status_code
            body = resp.text
        except Exception as e:
            logger.debug("Differential fuzzer request failed for %s: %s", mutated_url, e)
            continue

        normalized_candidate = normalize_response(body)
        diff_ratio = compute_diff_ratio(normalized_baseline, normalized_candidate)

        if diff_ratio > _DIFF_THRESHOLD:
            diffs = find_byte_level_diffs(normalized_baseline, normalized_candidate, context_bytes=32)
            top_diffs = diffs[:3]

            findings.append({
                'url': url,
                'endpoint_key': endpoint_key,
                'endpoint_base_key': endpoint_base,
                'endpoint_type': endpoint_type,
                'issues': ['differential_response_divergence'],
                'probe_type': 'differential_fuzzer',
                'severity': 'high',
                'confidence': min(0.9, diff_ratio),
                'evidence': {
                    'ratio': diff_ratio,
                    'diffs': top_diffs,
                    'url': mutated_url,
                    'payload': mutated_pairs[idx][1],
                    'status_code': status,
                    'parameter': param_name,
                    'strategy': 'bit_flip',
                },
            })
            logger.info("Differential fuzzer: divergence detected on %s (ratio=%.2f)", url, diff_ratio)

        if status >= 500 and base_status < 500:
            findings.append({
                'url': url,
                'endpoint_key': endpoint_key,
                'endpoint_base_key': endpoint_base,
                'endpoint_type': endpoint_type,
                'issues': ['differential_crash_triggered'],
                'probe_type': 'differential_fuzzer',
                'severity': 'medium',
                'confidence': 0.8,
                'evidence': {
                    'base_status_code': base_status,
                    'status_code': status,
                    'url': mutated_url,
                    'parameter': param_name,
                    'payload': mutated_pairs[idx][1],
                    'strategy': 'bit_flip',
                },
            })
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
