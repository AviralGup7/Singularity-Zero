import logging
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import build_manual_hint, build_validator_result, normalized_confidence
from src.core.models import ValidationResult
from src.execution.validators.validators.shared import (
    SSRF_CONFIDENCE_BASE,
    SSRF_CONFIDENCE_CAP,
    to_validation_result,
)

logger = logging.getLogger(__name__)

CALLBACK_READY_PARAMS = {
    "callback",
    "dest",
    "destination",
    "feed",
    "target",
    "uri",
    "url",
    "webhook",
}

# Parameters that are strong SSRF sinks (direct URL/host acceptance)
STRONG_SSRF_PARAMS = {
    "url",
    "uri",
    "dest",
    "destination",
    "target",
    "webhook",
    "callback",
    "redirect",
    "return",
    "return_to",
    "next",
    "continue",
    "forward",
    "goto",
    "link",
    "image",
    "img",
    "src",
    "source",
    "file",
    "path",
    "document",
    "pdf",
    "fetch",
    "load",
    "open",
    "download",
    "upload",
    "import",
    "export",
    "ping",
    "notify",
    "postback",
    "hook",
    "endpoint",
    "api_url",
    "server",
    "host",
    "ip",
    "proxy",
    "relay",
}

# Known internal/metadata IP ranges for edge case detection
INTERNAL_IP_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "169.254.",
    "0.",
    "::1",
    "fe80:",
    "fc00:",
    "fd00:",
)


def _is_internal_url(value: str) -> bool:
    """Check if a parameter value references an internal/metadata host."""
    lowered = value.lower().strip()
    if any(lowered.startswith(prefix) for prefix in INTERNAL_IP_PREFIXES):
        return True
    cloud_metadata = (
        "169.254.169.254",
        "metadata.google",
        "metadata.azure",
        "100.100.100.200",
        "168.63.129.16",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",  # nosec: S104
        "[::1]",
    )
    if any(meta in lowered for meta in cloud_metadata):
        return True
    encoded_internal = (
        "%31%32%37",
        "%31%30%30",
        "%31%39%32",
        "127%2e",
        "10%2e",
        "192%2e",
        "169%2e254",
    )
    if any(enc in lowered for enc in encoded_internal):
        return True
    dangerous_schemes = (
        "file://",
        "gopher://",
        "dict://",
        "ldap://",
        "ldaps://",
        "ftp://",
        "tftp://",
        "smb://",
    )
    if any(lowered.startswith(scheme) for scheme in dangerous_schemes):
        return True
    return False


def _assess_parameter_ssrf_risk(param_name: str, param_value: str) -> tuple[str, float]:
    """Assess SSRF risk for a specific parameter name/value pair."""
    lowered_name = param_name.lower().strip()
    if lowered_name in STRONG_SSRF_PARAMS:
        if _is_internal_url(param_value):
            return ("strong_sink", 0.9)
        return ("strong_sink", 0.7)
    if any(
        kw in lowered_name for kw in ("callback", "webhook", "postback", "hook", "notify", "ping")
    ):
        if _is_internal_url(param_value):
            return ("moderate_sink", 0.8)
        return ("moderate_sink", 0.6)
    try:
        parsed = urlparse(param_value)
        if (
            parsed.scheme in ("http", "https", "ftp", "file", "gopher", "dict", "ldap")
            and parsed.netloc
        ):
            if _is_internal_url(param_value):
                return ("moderate_sink", 0.75)
            return ("weak_indicator", 0.4)
    except Exception as exc:  # noqa: BLE001
        logger.debug("_assess_parameter_ssrf_risk parse error for %s: %s", param_value, exc)
    return ("unlikely", 0.1)


def validate_ssrf_candidates(
    analysis_results: dict[str, list[dict[str, Any]]],
    callback_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    callback_ready = (
        str((callback_context or {}).get("validation_state", "passive_only")).lower()
        == "active_ready"
    )
    token_present = bool((callback_context or {}).get("token_present"))
    findings: list[dict[str, Any]] = []

    for item in analysis_results.get("ssrf_candidate_finder", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        parameters = sorted(
            {
                str(value).strip().lower()
                for value in item.get("parameters", [])
                if str(value).strip()
            }
        )
        signals = sorted(
            {str(value).strip() for value in item.get("signals", []) if str(value).strip()}
        )
        score = int(item.get("score", 0))
        bonuses = []
        notes = []
        validation_state = "passive_only"
        risk_assessments = []

        # Assess each parameter's SSRF risk level
        param_values = item.get("param_values", {})
        for param in parameters:
            param_value = str(param_values.get(param, "")).strip()
            risk_level, risk_score = _assess_parameter_ssrf_risk(param, param_value)
            risk_assessments.append(
                {"parameter": param, "risk_level": risk_level, "risk_score": risk_score}
            )
            if risk_level == "strong_sink" and risk_score >= 0.8:
                bonuses.append(0.08)

        if any(signal.startswith("internal_host_reference:") for signal in signals):
            bonuses.append(0.11)
            notes.append("Includes a localhost or metadata-style reference in the parameter value.")
        if any(signal.startswith("dangerous_scheme:") for signal in signals):
            bonuses.append(0.12)
            notes.append("Accepts a dangerous URI scheme such as file, ftp, or gopher.")
        if any(signal.startswith("dns_like_payload:") for signal in signals):
            bonuses.append(0.08)
        if any(signal.startswith("oauth_adjacent_param:") for signal in signals):
            bonuses.append(0.07)
            notes.append(
                "OAuth-style callback parameters are present, so this flow may behave like an SSRF-adjacent sink."
            )
        if any(signal.startswith("cloud_metadata_reference:") for signal in signals):
            bonuses.append(0.15)
            notes.append("References a cloud metadata endpoint (AWS/GCP/Azure).")
        if any(signal.startswith("protocol_smuggling_attempt:") for signal in signals):
            bonuses.append(0.14)
            notes.append("Contains a protocol smuggling attempt (gopher/dict/ldap/smb).")
        if any(signal.startswith("encoded_internal_host:") for signal in signals):
            bonuses.append(0.13)
            notes.append("Contains an encoded internal host reference.")
        if any(signal.startswith("ipv4_address:") for signal in signals):
            bonuses.append(0.09)
            notes.append("Contains a direct IPv4 address reference.")
        if any(signal.startswith("ipv6_address:") for signal in signals):
            bonuses.append(0.09)
            notes.append("Contains a direct IPv6 address reference.")
        if any(signal.startswith("sensitive_port_reference:") for signal in signals):
            bonuses.append(0.08)
            notes.append("References a sensitive service port.")
        if any(signal.startswith("nested_scheme:") for signal in signals):
            bonuses.append(0.10)
            notes.append("Contains nested scheme indicators (multiple ://).")
        if any(signal.startswith("decimal_dns_exfil:") for signal in signals):
            bonuses.append(0.07)
            notes.append("Contains a decimal DNS exfiltration pattern.")
        if any(signal.startswith("dns_rebinding_service:") for signal in signals):
            bonuses.append(0.16)
            notes.append(
                "References a known DNS rebinding service — high-confidence SSRF indicator."
            )
        if any(signal.startswith("numeric_subdomain_dns:") for signal in signals):
            bonuses.append(0.10)
            notes.append(
                "Contains a numeric subdomain that may resolve to internal IPs (DNS rebinding pattern)."
            )
        if any(signal.startswith("data_blob_scheme:") for signal in signals):
            bonuses.append(0.06)
            notes.append("Contains data/blob URI scheme — potential client-side SSRF vector.")

        # Edge case: Check for public/external URL patterns (lower risk)
        has_external_only = all(
            not signal.startswith(
                (
                    "internal_host",
                    "cloud_metadata",
                    "encoded_internal",
                    "ipv4",
                    "ipv6",
                    "dangerous_scheme",
                    "protocol_smuggling",
                )
            )
            for signal in signals
        ) and all(r["risk_level"] in ("weak_indicator", "unlikely") for r in risk_assessments)
        if has_external_only and signals:
            bonuses.append(-0.05)
            notes.append("Only external/public URL patterns detected — lower SSRF likelihood.")

        # Edge case: Multiple strong sinks increase confidence
        strong_sink_count = sum(1 for r in risk_assessments if r["risk_level"] == "strong_sink")
        if strong_sink_count >= 2:
            bonuses.append(0.06)
            notes.append(
                f"Multiple strong SSRF sink parameters ({strong_sink_count}) increase confidence."
            )

        # Edge case: Check for URL encoding bypass attempts
        has_encoding_bypass = any(
            signal.startswith("encoded_internal")
            or signal.startswith("octal_ip")
            or signal.startswith("hex_ip")
            for signal in signals
        )
        if has_encoding_bypass:
            bonuses.append(0.07)
            notes.append(
                "URL encoding bypass patterns detected — suggests intentional internal host obfuscation."
            )

        if callback_ready and any(parameter in CALLBACK_READY_PARAMS for parameter in parameters):
            validation_state = "active_ready"
            bonuses.append(0.1)
        if token_present and validation_state == "active_ready":
            bonuses.append(0.05)
        confidence = normalized_confidence(
            base=SSRF_CONFIDENCE_BASE,
            score=score,
            signals=signals,
            bonuses=bonuses,
            cap=SSRF_CONFIDENCE_CAP,
        )
        findings.append(
            build_validator_result(
                module="ssrf_validation",
                category="ssrf",
                url=url,
                score=score,
                confidence=confidence,
                signals=signals,
                validation_state=validation_state,
                hint_message=build_manual_hint(
                    "ssrf",
                    url,
                    {"validation_state": validation_state, "risk_assessments": risk_assessments},
                ),
                parameters=parameters,
                notes=notes,
                risk_assessments=risk_assessments,
                strong_sink_count=strong_sink_count,
            )
        )

    findings.sort(key=lambda entry: (-entry["confidence"], -entry["score"], entry["url"]))
    return findings[:20]


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    analysis_results = {"ssrf_candidate_finder": [target]}
    callback_context = context.get("callback_context") if isinstance(context, dict) else None
    items = validate_ssrf_candidates(analysis_results, callback_context)
    if not items:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "failed"}, validator="ssrf", category="ssrf"
        )
    return to_validation_result(items[0], validator="ssrf", category="ssrf")
