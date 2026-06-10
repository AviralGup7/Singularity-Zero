"""Model-backed classification and reportability decisions for findings."""

from __future__ import annotations

from typing import Any

from src.intelligence.severity_model import enrich_finding_with_model_severity
from src.learning.signal_quality import score_signal_quality

FINDING_LOW_THRESHOLD = 0.45
FINDING_MEDIUM_THRESHOLD = 0.58
FINDING_HIGH_THRESHOLD = 0.72

FP_SUPPRESSION_PATTERNS: dict[str, dict[str, Any]] = {
    "rate_limit": {
        "status_codes": {429, 503},
        "body_indicators": ["rate limit", "too many requests", "throttl", "slow down"],
    },
    "waf_block": {
        "status_codes": {403, 406, 418},
        "body_indicators": ["blocked", "waf", "cloudflare", "akamai", "access denied"],
    },
    "cdn_error": {
        "status_codes": {502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527},
        "body_indicators": ["bad gateway", "service unavailable", "origin error"],
    },
    "generic_error": {
        "status_codes": {500, 501, 505},
        "body_indicators": ["internal server error", "not implemented"],
    },
}


def _is_likely_false_positive(status_code: int, body_text: str = "") -> tuple[bool, str]:
    """Return whether a response matches a known false-positive pattern."""

    body_lower = body_text.lower()
    for category, pattern in FP_SUPPRESSION_PATTERNS.items():
        if status_code in pattern["status_codes"] and any(
            indicator in body_lower for indicator in pattern["body_indicators"]
        ):
            return True, category
    return False, ""


def _get_dynamic_thresholds(target_profile: dict[str, Any] | None = None) -> dict[str, float]:
    """Compute adaptive low/medium/high reportability thresholds."""

    low = FINDING_LOW_THRESHOLD
    medium = FINDING_MEDIUM_THRESHOLD
    high = FINDING_HIGH_THRESHOLD
    if not target_profile:
        return {"low": low, "medium": medium, "high": high}

    if target_profile.get("api_heavy"):
        low -= 0.03
        medium -= 0.03
        high -= 0.02
    if target_profile.get("auth_complexity", 0) > 0.7:
        low += 0.04
        medium += 0.03
        high += 0.02

    historical_precision = target_profile.get("historical_precision")
    if historical_precision is not None:
        if historical_precision < 0.3:
            low += 0.05
            medium += 0.04
            high += 0.03
        elif historical_precision > 0.8:
            low -= 0.03
            medium -= 0.02
            high -= 0.02

    if str(target_profile.get("mode", "")).lower() in {"idor", "ssrf", "xss", "auth"}:
        low -= 0.05
        medium -= 0.04
        high -= 0.03

    low = max(0.25, min(low, 0.70))
    medium = max(low + 0.08, min(medium, 0.80))
    high = max(medium + 0.08, min(high, 0.90))
    return {"low": round(low, 2), "medium": round(medium, 2), "high": round(high, 2)}


def _diff_score(evidence: dict[str, Any]) -> tuple[int, str]:
    diff = evidence.get("diff", {}) if isinstance(evidence.get("diff"), dict) else {}
    score = 0
    classification = ""
    if diff.get("status_changed"):
        score += 2
        original = int(diff.get("original_status", 0) or 0)
        mutated = int(diff.get("mutated_status", 0) or 0)
        if original in {401, 403} and mutated == 200:
            score += 3
            classification = "auth_bypass_indicator"
        elif original == 200 and mutated in {401, 403}:
            score += 2
            classification = "auth_enforcement_change"
    if diff.get("redirect_changed"):
        score += 2
        classification = classification or "redirect_change"
    if diff.get("content_changed"):
        score += 1
    body_similarity = diff.get("body_similarity")
    if body_similarity is not None:
        similarity = float(body_similarity)
        if similarity < 0.3:
            score += 3
            classification = classification or "significant_content_change"
        elif similarity < 0.5:
            score += 2
        elif similarity < 0.7:
            score += 1
    return score, classification


def classify_finding(
    item: dict[str, Any],
    target_profile: dict[str, Any] | None = None,
    dynamic_fp_patterns: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Classify a finding using calibrated ML severity and TP/FP rates."""
    evidence = item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {}
    diff = evidence.get("diff", {}) if isinstance(evidence.get("diff"), dict) else {}
    diff_score, diff_classification = _diff_score(evidence)
    modeled = enrich_finding_with_model_severity(
        {
            **item,
            "diff_score": diff_score,
            "target_profile": target_profile or {},
            "dynamic_fp_patterns": dynamic_fp_patterns or [],
        }
    )
    signal_quality = score_signal_quality(modeled, dynamic_fp_patterns)
    severity_score = float(modeled.get("severity_score", 0.0))
    tp_probability = float(signal_quality.true_positive_probability)
    fp_probability = float(signal_quality.false_positive_probability)
    severity = str(modeled.get("severity", "info")).lower()
    confidence = float(item.get("confidence", 0.0) or 0.0)
    combined_signal = str(item.get("combined_signal", "")).strip()
    signal_count = len([part for part in combined_signal.split("+") if part.strip()])
    strong_confirmation = bool(
        evidence.get("reproducible")
        or evidence.get("confirmed")
        or evidence.get("intra_run_confirmed")
        or evidence.get("cross_run_reproducible")
        or evidence.get("trust_boundary_shift")
        or str(evidence.get("trust_boundary", "")).lower() == "cross-host"
    )

    mutated_status = int(diff.get("mutated_status", 0) or 0)
    fp_reason = ""
    if mutated_status:
        is_fp, fp_category = _is_likely_false_positive(
            mutated_status, str(evidence.get("body_snippet", ""))
        )
        if is_fp:
            fp_reason = f"Suppressed: matches {fp_category} false-positive pattern"

    if not signal_quality.reportable and not strong_confirmation:
        decision = "DROP"
    elif fp_reason and not strong_confirmation:
        decision = "DROP"
    elif severity in {"critical", "high"} or strong_confirmation or tp_probability >= 0.74:
        decision = "HIGH"
    elif severity == "medium" or tp_probability >= 0.58 or confidence >= FINDING_MEDIUM_THRESHOLD:
        decision = "MEDIUM"
    elif severity == "low" or signal_quality.action == "triage_low_priority" or signal_count:
        decision = "LOW"
    else:
        decision = "DROP"

    return {
        "decision": decision,
        "reason": (
            f"Signal-quality model {signal_quality.action} with calibrated severity "
            f"{severity} ({severity_score:.2f}/10), TP probability {tp_probability:.2%}, "
            f"and FP probability {fp_probability:.2%}."
        ),
        "confidence_factors": signal_quality.reasons
        or modeled.get("severity_model", {}).get("top_features", []),
        "suppress_reason": fp_reason
        or ("Model-calibrated likely false positive" if decision == "DROP" else ""),
        "diff_score": diff_score,
        "diff_classification": diff_classification,
        "thresholds_used": modeled.get("severity_model", {}).get("calibration", {}),
        "severity": severity,
        "severity_score": severity_score,
        "true_positive_probability": tp_probability,
        "false_positive_probability": fp_probability,
        "severity_model": modeled.get("severity_model", {}),
        "signal_quality": signal_quality.as_dict(),
        "signal_quality_score": signal_quality.quality_score,
    }


def annotate_finding_decisions(
    findings: list[dict[str, Any]],
    target_profile: dict[str, Any] | None = None,
    dynamic_fp_patterns: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Annotate each finding with model severity, decision, and reportability."""
    annotated = []
    for item in findings:
        classification = classify_finding(item, target_profile, dynamic_fp_patterns)
        modeled = enrich_finding_with_model_severity(item)
        decision = str(classification["decision"])
        annotated.append(
            {
                **modeled,
                "severity": classification.get("severity", modeled.get("severity")),
                "severity_score": classification.get(
                    "severity_score", modeled.get("severity_score", 0.0)
                ),
                "score": classification.get("severity_score", modeled.get("score", 0.0)),
                "true_positive_probability": classification.get(
                    "true_positive_probability", modeled.get("true_positive_probability", 0.0)
                ),
                "false_positive_probability": classification.get(
                    "false_positive_probability", modeled.get("false_positive_probability", 1.0)
                ),
                "severity_model": classification.get(
                    "severity_model", modeled.get("severity_model", {})
                ),
                "signal_quality": classification.get("signal_quality", {}),
                "signal_quality_score": classification.get("signal_quality_score", 0.0),
                "decision": decision,
                "reason": classification.get("reason", ""),
                "confidence_factors": classification.get("confidence_factors", []),
                "reportable": decision != "DROP",
                "suppress_reason": classification.get("suppress_reason", ""),
                "diff_score": classification.get("diff_score", 0),
                "diff_classification": classification.get("diff_classification", ""),
            }
        )
    return annotated


def filter_reportable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter findings to only those selected by the model-backed decision."""
    return [item for item in findings if str(item.get("decision", "MEDIUM")).upper() != "DROP"]
