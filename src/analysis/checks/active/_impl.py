import json
from typing import Any

from src.analysis.helpers import ensure_endpoint_key, meaningful_query_pairs
from src.analysis.passive.extended_shared import (
    AI_MODEL_RE,
    AI_PATH_TOKENS,
    COMMAND_ERROR_RE,
    COMMAND_PARAM_NAMES,
    FILE_ERROR_RE,
    FILE_PARAM_NAMES,
    RACE_BODY_KEYWORDS,
    RACE_PARAM_NAMES,
    RACE_PATH_KEYWORDS,
    SQL_ERROR_RE,
    SQL_PARAM_NAMES,
    THIRD_PARTY_KEY_PATTERNS,
    XML_ERROR_RE,
    XML_PARAM_NAMES,
    XSS_DANGEROUS_VALUE_RE,
    XSS_FIELD_RE,
    build_reflection_probe_mutation,
    record,
    reflection_context_signals,
    xss_signals,
)
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url


def stored_xss_signal_detector(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    seen: set[tuple[str, str]] = set()
    for response in responses:
        url = str(response.get("url", ""))
        body = (response.get("body_text") or "")[:12000]
        content_type = str(response.get("content_type", "")).lower()
        if "json" not in content_type and not body.lstrip().startswith(("{", "[")):
            continue
        # Check HTML-style field patterns
        for match in XSS_FIELD_RE.finditer(body):
            value = match.group("value")
            if not XSS_DANGEROUS_VALUE_RE.search(value):
                continue
            field = match.group("field").lower()
            dedupe_key = (url, field)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(
                record(
                    url,
                    status_code=response.get("status_code"),
                    indicator="stored_xss_candidate",
                    field=field,
                    xss_signals=xss_signals(value),
                    value_preview=value[:120],
                )
            )
        # Also check JSON field values for XSS patterns
        if body.lstrip().startswith(("{", "[")):
            try:
                data = json.loads(body)
                _scan_json_for_xss(data, url, response.get("status_code"), findings, seen)
            except (json.JSONDecodeError, ValueError):
                pass
    return findings[:80]


def _scan_json_for_xss(
    data: Any,
    url: str,
    status_code: Any,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
) -> None:
    """Recursively scan JSON data for XSS patterns in string values."""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str) and XSS_DANGEROUS_VALUE_RE.search(value):
                dedupe_key = (url, key.lower())
                if dedupe_key not in seen:
                    seen.add(dedupe_key)
                    findings.append(
                        record(
                            url,
                            status_code=status_code,
                            indicator="stored_xss_candidate",
                            field=key.lower(),
                            xss_signals=xss_signals(value),
                            value_preview=value[:120],
                        )
                    )
            elif isinstance(value, (dict, list)):
                _scan_json_for_xss(value, url, status_code, findings, seen)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                _scan_json_for_xss(item, url, status_code, findings, seen)


def reflected_xss_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 6
) -> list[dict[str, Any]]:
    findings = []
    seen: set[str] = set()
    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        mutation = build_reflection_probe_mutation(url)
        if not mutation:
            continue
        response = response_cache.request(
            mutation["mutated_url"],
            headers={"Cache-Control": "no-cache", "X-Codex-Reflection-Probe": "1"},
        )
        if not response:
            continue
        body = (response.get("body_text") or "")[:12000]
        if mutation["reflection_value"] not in body:
            continue
        findings.append(
            record(
                url,
                status_code=response.get("status_code"),
                indicator="reflected_input_candidate",
                parameter=mutation["parameter"],
                mutated_url=mutation["mutated_url"],
                reflection_value=mutation["reflection_value"],
                xss_signals=reflection_context_signals(body, mutation["reflection_value"]),
                content_type=response.get("content_type", ""),
            )
        )
        if len(findings) >= limit:
            break
    return findings


def race_condition_signal_analyzer(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    findings = []
    response_by_url = {
        str(item.get("url", "")).strip(): item for item in responses if item.get("url")
    }
    for url in sorted(urls):
        lowered = url.lower()
        path_signals = [token.strip("/") for token in RACE_PATH_KEYWORDS if token in lowered]
        query_names = [name for name, _ in meaningful_query_pairs(url)]
        param_signals = sorted({name for name in query_names if name in RACE_PARAM_NAMES})
        response = response_by_url.get(normalize_url(url))
        body = ((response or {}).get("body_text") or "").lower()[:4000]
        body_signals = sorted({token for token in RACE_BODY_KEYWORDS if token in body})
        if len(path_signals) + len(param_signals) + len(body_signals) < 2:
            continue
        signals = [
            *(f"path:{token}" for token in path_signals),
            *(f"param:{token}" for token in param_signals),
            *(f"body:{token}" for token in body_signals[:6]),
        ]
        if response:
            headers = {
                str(key).lower(): str(value)
                for key, value in (response.get("headers") or {}).items()
            }
            if not any(
                header in headers for header in ("etag", "idempotency-key", "x-idempotency-key")
            ):
                signals.append("missing_idempotency_hint")
        findings.append(
            record(
                url,
                status_code=(response or {}).get("status_code"),
                indicator="race_condition_candidate",
                signals=sorted(set(signals)),
                endpoint_family="booking_or_stateful_flow"
                if any(
                    token in lowered
                    for token in ("/book", "/booking", "/reservation", "/checkout", "/payment")
                )
                else "stateful_flow",
            )
        )
    return findings[:80]


def ai_endpoint_exposure_analyzer(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    findings = []
    response_by_url = {
        str(item.get("url", "")).strip(): item for item in responses if item.get("url")
    }
    for url in sorted(urls):
        lowered = url.lower()
        signals = [f"path:{token.strip('/')}" for token in AI_PATH_TOKENS if token in lowered]
        response = response_by_url.get(normalize_url(url))
        body = ((response or {}).get("body_text") or "")[:12000]
        provider_hints = sorted(
            {
                provider
                for provider in ("openai", "anthropic", "gemini", "llama", "mistral")
                if provider in body.lower() or provider in lowered
            }
        )
        model_hints = sorted({match.group(1) for match in AI_MODEL_RE.finditer(body)})[:8]
        provider_key_indicators = [
            label
            for label, pattern in THIRD_PARTY_KEY_PATTERNS
            if "api_key" in label and pattern.search(body)
        ]
        if "/models" in lowered or lowered.endswith("/models"):
            signals.append("model_enumeration_path")
        if model_hints:
            signals.append("model_family_hint")
        if provider_key_indicators:
            signals.append("provider_key_exposed")
        if not signals:
            continue
        findings.append(
            record(
                url,
                status_code=(response or {}).get("status_code"),
                signals=sorted(set(signals)),
                provider_hints=provider_hints,
                model_family_hints=model_hints,
                provider_key_indicators=sorted(provider_key_indicators),
                model_enumeration_path="/models" in lowered,
            )
        )
    return findings[:80]


def server_side_injection_surface_analyzer(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    findings = []
    response_by_url = {
        str(item.get("url", "")).strip(): item for item in responses if item.get("url")
    }
    for url in sorted(urls):
        query_pairs = meaningful_query_pairs(url)
        query_names = {name for name, _ in query_pairs}
        lowered = url.lower()
        response = response_by_url.get(normalize_url(url))
        body = ((response or {}).get("body_text") or "")[:8000]
        content_type = str((response or {}).get("content_type", "")).lower()
        vulnerability_types = set()
        signals: set[str] = set()
        if query_names & SQL_PARAM_NAMES or any(
            token in lowered for token in ("/query", "/report", "/search", "/filter")
        ):
            signals.update(f"param:{name}" for name in sorted(query_names & SQL_PARAM_NAMES))
            if SQL_ERROR_RE.search(body):
                signals.add("response_error_hint")
            if len(signals) >= 2 or "response_error_hint" in signals:
                vulnerability_types.add("sql_injection")
        if query_names & FILE_PARAM_NAMES or any(
            token in lowered
            for token in ("/download", "/file", "/include", "/render", "/template", "/view")
        ):
            signals.update(f"param:{name}" for name in sorted(query_names & FILE_PARAM_NAMES))
            if FILE_ERROR_RE.search(body):
                signals.add("response_error_hint")
            if len(signals) >= 2 or "response_error_hint" in signals:
                vulnerability_types.add("local_file_inclusion")
        if query_names & XML_PARAM_NAMES or "xml" in lowered or "application/xml" in content_type:
            signals.update(f"param:{name}" for name in sorted(query_names & XML_PARAM_NAMES))
            if XML_ERROR_RE.search(body):
                signals.add("response_error_hint")
            if len(signals) >= 2 or "response_error_hint" in signals:
                vulnerability_types.add("xxe")
        if query_names & COMMAND_PARAM_NAMES or any(
            token in lowered for token in ("/cmd", "/command", "/exec", "/run", "/task")
        ):
            signals.update(f"param:{name}" for name in sorted(query_names & COMMAND_PARAM_NAMES))
            if COMMAND_ERROR_RE.search(body):
                signals.add("response_error_hint")
            if len(signals) >= 2 or "response_error_hint" in signals:
                vulnerability_types.update({"command_injection", "remote_code_execution"})
        if not vulnerability_types:
            continue
        findings.append(
            record(
                url,
                status_code=(response or {}).get("status_code"),
                vulnerability_types=sorted(vulnerability_types),
                signals=sorted(signals),
                content_type=(response or {}).get("content_type", ""),
            )
        )
    return findings[:80]
