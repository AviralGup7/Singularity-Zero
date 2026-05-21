"""Execution wrappers and helpers for running active probes."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, cast
from urllib.parse import parse_qsl, urlparse

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


def _extract_jwt_candidates(url: str, cached_response: Any, *, probes: dict[str, Any]) -> list[str]:
    token_re = probes["jwt_token_regex"]
    if token_re is None:
        return []

    tokens: set[str] = set()
    for _, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        tokens.update(token_re.findall(str(value)))

    if isinstance(cached_response, dict):
        headers = cached_response.get("headers")
        if isinstance(headers, dict):
            for header_value in headers.values():
                tokens.update(token_re.findall(str(header_value)))
        body_text = str(cached_response.get("body_text") or cached_response.get("body") or "")
        if body_text:
            tokens.update(token_re.findall(body_text[:12000]))

    return sorted(tokens)


def _run_jwt_attack_suite(
    priority_items: list[dict[str, Any]],
    shared_response_cache: Any,
    max_targets: int = 2,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    try:
        import requests
    except (ImportError, TypeError, ValueError, AttributeError):
        return []

    findings: list[dict[str, Any]] = []
    tested = 0
    for item in priority_items:
        if tested >= max_targets:
            break

        url = str(item.get("url", "")).strip()
        if not url:
            continue

        cached_response = (
            shared_response_cache.get(url) if hasattr(shared_response_cache, "get") else None
        )
        tokens = _extract_jwt_candidates(url, cached_response, probes=probes)
        if not tokens:
            continue

        token = tokens[0]
        session = requests.Session()
        tested += 1
        result = probes["run_jwt_attack_suite"](token, url, session, config=None)
        if not isinstance(result, dict):
            continue

        vulnerable_attacks = int(result.get("vulnerable_attacks", 0) or 0)
        if vulnerable_attacks <= 0:
            continue

        vulnerable_list = result.get("vulnerable_list", [])
        issues = [f"jwt_attack_{name}" for name in vulnerable_list if str(name).strip()]
        if not issues:
            issues = ["jwt_attack_suite_vulnerable"]

        findings.append(
            {
                "url": url,
                "endpoint_key": url,
                "endpoint_base_key": url.split("?", 1)[0],
                "endpoint_type": "API",
                "issues": issues,
                "probe_type": "jwt_attack_suite",
                "severity": str(result.get("severity", "high") or "high"),
                "confidence": round(min(0.95, 0.6 + vulnerable_attacks * 0.05), 2),
                "evidence": {
                    "vulnerable_attacks": vulnerable_attacks,
                    "vulnerable_list": vulnerable_list,
                    "token_preview": str(result.get("token_preview", "")),
                },
            }
        )

    return findings


def _run_fuzzing_suggestion_probe(
    priority_urls: list[str],
    limit: int = 12,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    parameter_suggestions = probes["generate_payload_suggestions"](
        priority_urls,
        limit=limit,
    )
    header_suggestions = probes["generate_header_payloads"](
        priority_urls,
        limit=limit,
    )
    body_suggestions = probes["generate_body_payloads"](
        priority_urls,
        limit=limit,
    )

    per_url: dict[str, dict[str, Any]] = {}

    def _entry_for(url: str) -> dict[str, Any]:
        base = per_url.get(url)
        if isinstance(base, dict):
            return base
        record = {
            "url": url,
            "endpoint_key": url,
            "endpoint_base_key": url.split("?", 1)[0],
            "endpoint_type": "API",
            "issues": ["fuzzing_payload_candidates_generated"],
            "probe_type": "fuzzing_suggestions",
            "parameter_suggestion_count": 0,
            "header_suggestion_count": 0,
            "body_suggestion_count": 0,
            "sample_payloads": {},
        }
        per_url[url] = record
        return record

    if isinstance(parameter_suggestions, list):
        for item in parameter_suggestions:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            entry = _entry_for(url)
            suggestions = item.get("suggestions")
            if isinstance(suggestions, list):
                entry["parameter_suggestion_count"] += len(suggestions)
                if suggestions and "parameter" not in entry["sample_payloads"]:
                    entry["sample_payloads"]["parameter"] = suggestions[:3]

    if isinstance(header_suggestions, list):
        for item in header_suggestions:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            entry = _entry_for(url)
            suggestions = item.get("header_suggestions")
            if isinstance(suggestions, list):
                entry["header_suggestion_count"] += len(suggestions)
                if suggestions and "header" not in entry["sample_payloads"]:
                    entry["sample_payloads"]["header"] = suggestions[:3]

    if isinstance(body_suggestions, list):
        for item in body_suggestions:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            entry = _entry_for(url)
            suggestions = item.get("body_suggestions")
            if isinstance(suggestions, list):
                entry["body_suggestion_count"] += len(suggestions)
                if suggestions and "body" not in entry["sample_payloads"]:
                    entry["sample_payloads"]["body"] = suggestions[:3]

    findings: list[dict[str, Any]] = []
    for item in per_url.values():
        total = (
            int(item.get("parameter_suggestion_count", 0) or 0)
            + int(item.get("header_suggestion_count", 0) or 0)
            + int(item.get("body_suggestion_count", 0) or 0)
        )
        if total <= 0:
            continue
        item["confidence"] = 0.35
        item["severity"] = "info"
        item["evidence"] = {
            "total_suggestions": total,
            "parameter_suggestions": int(item.get("parameter_suggestion_count", 0) or 0),
            "header_suggestions": int(item.get("header_suggestion_count", 0) or 0),
            "body_suggestions": int(item.get("body_suggestion_count", 0) or 0),
        }
        findings.append(item)

    findings.sort(
        key=lambda finding: (
            -int((finding.get("evidence", {}) or {}).get("total_suggestions", 0)),
            str(finding.get("url", "")),
        )
    )
    return findings[:limit]


async def _try_probe(
    name: str,
    probe_fn: Any,
    *args: Any,
    timeout_seconds: float | None = None,
    error_accumulator: list[dict[str, Any]] | None = None,
    **kwargs: Any,
) -> tuple[str, list[dict[str, Any]], bool]:
    """Run a probe, return (name, findings, success)."""

    async def _execute_probe() -> object:
        if inspect.iscoroutinefunction(probe_fn):
            return await probe_fn(*args, **kwargs)

        result = await asyncio.to_thread(probe_fn, *args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result

    try:
        if timeout_seconds is not None and timeout_seconds > 0:
            result = await asyncio.wait_for(_execute_probe(), timeout=timeout_seconds)
        else:
            result = await _execute_probe()
        findings = cast(
            list[dict[str, Any]],
            result if isinstance(result, list) else ([result] if result else []),
        )
        return name, findings, True
    except TimeoutError:
        msg = f"Probe '{name}' timed out after {timeout_seconds}s"
        logger.warning(msg)
        if error_accumulator is not None:
            error_accumulator.append({"probe": name, "reason": "timeout", "message": msg})
        return name, [], False
    except Exception as exc:
        msg = f"Probe '{name}' failed: {exc}"
        logger.warning(msg)
        if error_accumulator is not None:
            error_accumulator.append({"probe": name, "reason": "error", "message": msg})
        return name, [], False
