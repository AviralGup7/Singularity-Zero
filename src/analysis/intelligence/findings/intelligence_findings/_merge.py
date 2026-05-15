"""Core finding construction and anomaly helper logic."""

import json
from typing import Any

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    is_auth_flow_endpoint,
    resolve_endpoint_key,
)
from src.core.contracts.pipeline import dedup_digest, dedup_key

from ._categories import MITRE_ATTACK_MAPPING, SEVERITY_SCORES


def _with_anomaly(item: dict[str, Any], anomaly_keys: set[str]) -> dict[str, Any]:
    copied = dict(item)
    if resolve_endpoint_key(copied) in anomaly_keys:
        copied["signals"] = sorted(set(copied.get("signals", [])) | {"priority_plus_anomaly"})
    return copied


def _finding(
    module: str,
    category: str,
    severity: str,
    title: str,
    url: str,
    evidence: dict[str, Any],
    priority_bonus: int,
    next_step: str,
    seen: set[tuple[str, str, str, str]],
) -> dict[str, Any]:
    """Build a single finding dict with scoring and metadata."""
    from ._explanations import build_explanation
    from ._scoring import confidence_for_evidence, confidence_reasoning

    endpoint_base = str(evidence.get("endpoint_base_key") or endpoint_base_key(url))
    endpoint_type = str(
        evidence.get("endpoint_type") or classify_endpoint(url) or "GENERAL"
    ).upper()
    dedupe_key = (module, category, endpoint_base, title)
    if dedupe_key in seen:
        return {}
    seen.add(dedupe_key)
    evidence_text = json.dumps(evidence, sort_keys=True)
    finding_id = dedup_digest(dedup_key(module, category, endpoint_base, title, evidence_text))
    score = SEVERITY_SCORES.get(severity, 15) + min(priority_bonus, 25)
    if evidence.get("comparison"):
        score += 10
    if evidence.get("location") == "referer_risk":
        score += 8
    if evidence.get("validation_state") == "active_ready":
        score += 8
    if evidence.get("auth_flow_endpoint") or is_auth_flow_endpoint(url):
        score += 4
    if endpoint_type in {"AUTH", "STATIC"}:
        score -= 6
    signal_tokens = {str(signal).lower() for signal in evidence.get("signals", [])}
    combined = []
    if endpoint_type == "AUTH" or evidence.get("auth_flow_endpoint") or is_auth_flow_endpoint(url):
        combined.append("auth")
    if category == "open_redirect" or any("redirect" in signal for signal in signal_tokens):
        combined.append("redirect")
    if category == "token_leak" or any("token" in signal for signal in signal_tokens):
        combined.append("token")
    if category == "ssrf":
        combined.append("ssrf")
    combined_signal = " + ".join(dict.fromkeys(combined))
    if len(combined) >= 3:
        score += 10
    if "priority_plus_anomaly" in signal_tokens:
        score += 4
    confidence = confidence_for_evidence(module, evidence)
    confidence_reason = confidence_reasoning(module, evidence, confidence)
    mitre_techniques = MITRE_ATTACK_MAPPING.get(category, [])

    return {
        "id": finding_id,
        "module": module,
        "category": category,
        "severity": severity,
        "score": score,
        "confidence": confidence,
        "confidence_explanation": confidence_reason,
        "title": title,
        "url": url,
        "endpoint_type": endpoint_type,
        "combined_signal": combined_signal,
        "likely_exploitable_flow": len(combined) >= 3,
        "next_step": next_step,
        "explanation": build_explanation(
            module, category, severity, title, evidence, combined_signal
        ),
        "evidence": evidence,
        "mitre_attack": mitre_techniques,
    }
