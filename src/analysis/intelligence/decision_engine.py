"""Decision engine for classifying and prioritizing security findings.

Provides finding classification based on confidence scores, evidence quality,
signal correlation, and trust boundary analysis.
Supports dynamic thresholds that adapt to target profile and context.
Includes false-positive suppression for known noise patterns (WAF, rate limits, CDN errors).
"""

from typing import Any

# Base finding classification thresholds (used when no target profile is provided)
FINDING_LOW_THRESHOLD = 0.45
FINDING_MEDIUM_THRESHOLD = 0.58
FINDING_HIGH_THRESHOLD = 0.72

# Diff score thresholds for finding elevation
DIFF_SCORE_ELEVATED = 2
DIFF_SCORE_CRITICAL = 3

# Category-specific threshold adjustments
# Some finding types warrant lower thresholds (higher sensitivity) due to their severity
CATEGORY_SENSITIVITY: dict[str, float] = {
    "token_leak": -0.08,  # Token leaks are high-impact, lower threshold
    "ssrf": -0.06,  # SSRF can lead to internal network access
    "idor": -0.05,  # IDOR is common and impactful
    "access_control": -0.05,  # Auth bypasses are critical
    "xss": -0.04,  # XSS is well-understood, lower false positive rate
    "payment": -0.06,  # Payment issues are high-impact
    "trust_boundary_shift": -0.10,  # Cross-host shifts are always significant
    "confirmed": -0.08,  # Confirmed findings need less additional evidence
    "anomaly": 0.05,  # Anomalies are noisy, raise threshold
    "exposure": 0.03,  # Information exposure is often low-severity
    "misconfiguration": 0.02,  # Misconfigs are common, slightly raise threshold
    "sql_injection": -0.07,  # SQLi is critical, lower threshold
    "csrf": -0.05,  # CSRF can lead to account takeover
    "ssti": -0.06,  # SSTI can lead to RCE
    "file_upload": -0.05,  # File upload can lead to RCE
    "http_smuggling": -0.07,  # HTTP smuggling is critical
    "jwt_security": -0.04,  # JWT issues can lead to auth bypass
    "rate_limit_bypass": -0.03,  # Rate limit bypass enables abuse
    "business_logic": -0.04,  # Business logic flaws can be high-impact
    "graphql": -0.03,  # GraphQL issues are often informational
}

# Endpoint-type specific threshold adjustments
# Static endpoints are less likely to have real vulnerabilities
ENDPOINT_TYPE_SENSITIVITY: dict[str, float] = {
    "STATIC": 0.10,  # Static assets are unlikely to be vulnerable
    "ASSET": 0.05,  # Static assets like images, CSS
    "DOCUMENTATION": 0.08,  # Docs pages are low-risk
    "API": -0.03,  # APIs are more likely to have logic flaws
    "AUTH": -0.05,  # Auth endpoints are high-value targets
    "ADMIN": -0.06,  # Admin panels are critical
    "GENERAL": 0.0,  # Default adjustment
}

# Known false-positive response patterns that should suppress findings
FP_SUPPRESSION_PATTERNS: dict[str, dict[str, Any]] = {
    # Rate limiting responses
    "rate_limit": {
        "status_codes": {429, 503},
        "body_indicators": [
            "rate limit",
            "too many requests",
            "throttl",
            "slow down",
            "try again later",
        ],
    },
    # WAF/CDN blocking responses
    "waf_block": {
        "status_codes": {403, 406, 418},
        "body_indicators": [
            "blocked",
            "waf",
            "cloudflare",
            "akamai",
            "incapsula",
            "forbidden",
            "access denied",
        ],
    },
    # CDN error pages
    "cdn_error": {
        "status_codes": {502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 527},
        "body_indicators": [
            "bad gateway",
            "service unavailable",
            "origin error",
            "connection timed out",
        ],
    },
    # Generic error pages (not mutation-specific)
    "generic_error": {
        "status_codes": {500, 501, 505},
        "body_indicators": [
            "internal server error",
            "not implemented",
            "http version not supported",
        ],
    },
}


def _is_likely_false_positive(status_code: int, body_text: str = "") -> tuple[bool, str]:
    """Check if a response matches known false-positive patterns.

    Args:
        status_code: HTTP status code of the response.
        body_text: Response body text to check for FP indicators.

    Returns:
        Tuple of (is_fp, fp_category) where fp_category is empty string if not FP.
    """
    body_lower = body_text.lower()
    for category, pattern in FP_SUPPRESSION_PATTERNS.items():
        if status_code in pattern["status_codes"]:
            if any(indicator in body_lower for indicator in pattern["body_indicators"]):
                return True, category
    return False, ""


def _get_dynamic_thresholds(target_profile: dict[str, Any] | None = None) -> dict[str, float]:
    """Compute adaptive classification thresholds based on target profile.

    Adjusts thresholds based on:
    - api_heavy: API-heavy targets get slightly lower thresholds (more findings expected)
    - auth_complexity: Complex auth targets get higher thresholds (more noise)
    - historical_precision: Low precision from previous runs raises thresholds
    - mode: Focused modes (e.g., 'idor') lower thresholds for that category

    Args:
        target_profile: Optional dict with api_heavy, auth_complexity,
                       historical_precision, and mode keys.

    Returns:
        Dict with low, medium, high threshold values.
    """
    low = FINDING_LOW_THRESHOLD
    medium = FINDING_MEDIUM_THRESHOLD
    high = FINDING_HIGH_THRESHOLD

    if not target_profile:
        return {"low": low, "medium": medium, "high": high}

    # API-heavy targets: slightly lower thresholds (more signal expected)
    if target_profile.get("api_heavy"):
        low -= 0.03
        medium -= 0.03
        high -= 0.02

    # High auth complexity: raise thresholds to reduce noise
    if target_profile.get("auth_complexity", 0) > 0.7:
        low += 0.04
        medium += 0.03
        high += 0.02

    # Historical precision feedback: adjust based on past accuracy
    historical_precision = target_profile.get("historical_precision")
    if historical_precision is not None:
        if historical_precision < 0.3:
            # Low precision: raise thresholds to reduce false positives
            low += 0.05
            medium += 0.04
            high += 0.03
        elif historical_precision > 0.8:
            # High precision: lower thresholds to catch more
            low -= 0.03
            medium -= 0.02
            high -= 0.02

    # Focused mode: lower threshold for the target category
    mode = str(target_profile.get("mode", "")).lower()
    if mode in {"idor", "ssrf", "xss", "auth"}:
        low -= 0.05
        medium -= 0.04

    # Clamp thresholds to valid range
    low = max(0.25, min(low, 0.70))
    medium = max(low + 0.08, min(medium, 0.80))
    high = max(medium + 0.08, min(high, 0.90))

    return {"low": round(low, 2), "medium": round(medium, 2), "high": round(high, 2)}


def classify_finding(
    item: dict[str, Any], target_profile: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Classify a security finding as HIGH, MEDIUM, Low, or DROP.

    Classification Algorithm Overview:
    ───────────────────────────────────
    1. Dynamic Thresholds: Compute adaptive LOW/MEDIUM/HIGH thresholds based on
       target_profile (api_heavy, auth_complexity, historical_precision, mode).
       Category-specific adjustments (CATEGORY_SENSITIVITY) lower thresholds for
       high-impact finding types (sql_injection, ssrf, etc.) and raise for
       noisy types (anomaly, misconfiguration).
    2. Endpoint-type adjustments (ENDPOINT_TYPE_SENSITIVITY) further tune
       thresholds — ADMIN/API endpoints get lower thresholds, STATIC/ASSET
       endpoints get higher thresholds.
    3. Diff Score Computation: Analyze evidence["diff"] for status changes,
       body_similarity, redirect changes. Auth-related transitions (200→401/403,
       401/403→200) score highest. Body similarity <0.3 adds +3 to diff_score.
    4. Signal Correlation: Track reproducible, intra_run_confirmed, and
       cross_run_reproducible flags. Cross-run reproducibility is the strongest
       signal and adds +2 to diff_score.
    5. Trust Boundary: Trust_boundary_shift always elevates to HIGH.
    6. Decision Tree:
       - Trust boundary shift → HIGH
       - Cross-run reproducible + diff_score >= 1 → HIGH
       - Reproducible + diff_score >= 2 → HIGH
       - Intra-run confirmed + diff_score >= 2 → HIGH
       - High confidence + supporting evidence → HIGH
       - Moderate confidence or confirmed or high signal → MEDIUM
       - Low confidence + any signal → LOW
       - Below threshold with no evidence → DROP
    7. False-Positive Suppression: Check mutated status against known FP patterns
       (rate_limit, waf_block, cdn_error, generic_error). Downgrade or DROP
       matching findings unless they have strong confirmation signals.

    Args:
        item: Finding dict with confidence, evidence, combined_signal, etc.
        target_profile: Optional dict for dynamic threshold adjustment.

    Returns:
        Dict with 'decision' (HIGH/MEDIUM/LOW/DROP), 'reason' (explanation),
        'confidence_factors' (list of factors that influenced the decision),
        and 'suppress_reason' (if suppressed by FP patterns).
    """
    thresholds = _get_dynamic_thresholds(target_profile)
    confidence = float(item.get("confidence", 0))
    evidence = item.get("evidence", {}) or {}
    combined_signal = str(item.get("combined_signal", "")).strip()
    severity = str(item.get("severity", "")).lower()
    reasons: list[str] = []
    confidence_factors: list[str] = []

    # Apply category-specific threshold adjustments
    category_adjustment = 0.0
    signals_list = [s.strip().lower() for s in combined_signal.split("+") if s.strip()]
    for sig in signals_list:
        if sig in CATEGORY_SENSITIVITY:
            category_adjustment = min(category_adjustment, CATEGORY_SENSITIVITY[sig])
    # Also check severity-based adjustment
    if severity in CATEGORY_SENSITIVITY:
        category_adjustment = min(category_adjustment, CATEGORY_SENSITIVITY[severity])

    # Apply endpoint-type specific threshold adjustments
    endpoint_type = str(item.get("endpoint_type", "")).upper()
    endpoint_type_adjustment = ENDPOINT_TYPE_SENSITIVITY.get(endpoint_type, 0.0)

    # Combine all adjustments
    total_adjustment = category_adjustment + endpoint_type_adjustment

    # Apply adjustments to thresholds
    adj_low = max(0.20, thresholds["low"] + total_adjustment)
    adj_medium = max(adj_low + 0.08, thresholds["medium"] + total_adjustment)
    adj_high = max(adj_medium + 0.08, thresholds["high"] + total_adjustment)
    reproducible = bool(evidence.get("reproducible") or evidence.get("confirmed"))
    intra_run_confirmed = bool(evidence.get("intra_run_confirmed"))
    cross_run_reproducible = bool(evidence.get("cross_run_reproducible"))
    diff = evidence.get("diff", {}) if isinstance(evidence.get("diff"), dict) else {}
    trust_boundary = (
        bool(evidence.get("trust_boundary_shift"))
        or str(evidence.get("trust_boundary", "")).lower() == "cross-host"
    )

    # Compute diff score with richer semantics aligned to response_filter classifications
    diff_score = 0
    diff_classification = ""
    if diff.get("status_changed"):
        diff_score += 2
        # Auth-related status changes carry higher significance
        status_from = int(diff.get("original_status", 0) or 0)
        status_to = int(diff.get("mutated_status", 0) or 0)
        if status_from == 200 and status_to in {401, 403}:
            diff_score += 2  # Auth enforcement triggered
            diff_classification = "auth_enforcement_change"
            reasons.append(f"Auth enforcement: {status_from} → {status_to}")
        elif status_from in {401, 403} and status_to == 200:
            diff_score += 3  # Auth bypass indicator
            diff_classification = "auth_bypass_indicator"
            reasons.append(f"Auth bypass indicator: {status_from} → {status_to}")
            confidence_factors.append("auth_bypass_status_change")
        elif status_to == 500:
            diff_score += 1  # Server error from mutation
            diff_classification = "server_error_trigger"
            reasons.append(f"Server error triggered: {status_from} → {status_to}")
    if diff.get("redirect_changed"):
        diff_score += 2
        diff_classification = diff_classification or "redirect_change"
        reasons.append("Redirect chain changed")
    if diff.get("content_changed"):
        diff_score += 1
        reasons.append("Response content changed")
    body_sim_raw = diff.get("body_similarity")
    body_sim = float(body_sim_raw) if body_sim_raw is not None else 1.0
    if body_sim < 0.3:
        diff_score += 3
        diff_classification = diff_classification or "significant_content_change"
        reasons.append(f"Body similarity very low ({body_sim:.2f})")
        confidence_factors.append("significant_body_change")
    elif body_sim < 0.5:
        diff_score += 2  # Moderate body change is still meaningful
        reasons.append(f"Body similarity moderate ({body_sim:.2f})")
    elif body_sim < 0.7:
        diff_score += 1  # Slight body change adds weak signal
        reasons.append(f"Body similarity slightly reduced ({body_sim:.2f})")

    # Track confidence factors
    if reproducible:
        confidence_factors.append("reproducible")
        reasons.append("Finding is reproducible across runs")
    if intra_run_confirmed:
        confidence_factors.append("intra_run_confirmed")
        reasons.append("Confirmed within same run via multi-mutation")
    if cross_run_reproducible:
        confidence_factors.append("cross_run_reproducible")
        reasons.append("Reproducible across multiple scan runs (strongest signal)")
        # Cross-run reproducibility is the strongest signal — boost classification
        diff_score += 2
    if trust_boundary:
        confidence_factors.append("trust_boundary_shift")
        reasons.append("Trust boundary crossed")

    # Classification logic with reasoning
    decision = "DROP"

    # Compute high_signal AFTER all diff_score modifications
    high_signal = (
        len([part for part in combined_signal.split("+") if part.strip()]) >= 2
        or diff_score >= DIFF_SCORE_CRITICAL
    )
    if high_signal:
        confidence_factors.append("high_signal_correlation")

    # Trust boundary shifts are always HIGH
    if trust_boundary:
        decision = "HIGH"
        reasons.append("Elevated to HIGH: trust boundary shift")
    # Cross-run reproducibility with any diff signal is HIGH
    elif cross_run_reproducible and diff_score >= 1:
        decision = "HIGH"
        reasons.append("Elevated to HIGH: cross-run reproducible with response change")
    # Strong confirmation alone is sufficient for HIGH
    elif reproducible and diff_score >= DIFF_SCORE_ELEVATED:
        decision = "HIGH"
        reasons.append("Elevated to HIGH: reproducible with significant diff")
    elif intra_run_confirmed and diff_score >= DIFF_SCORE_ELEVATED:
        decision = "HIGH"
        reasons.append("Elevated to HIGH: intra-run confirmed with significant diff")
    # Strong intra-run confirmation without diff is still HIGH for sensitive categories
    elif intra_run_confirmed and category_adjustment < 0:
        decision = "HIGH"
        reasons.append(
            f"Elevated to HIGH: intra-run confirmed in sensitive category (adjustment: {category_adjustment})"
        )
    # HIGH: high confidence with supporting evidence
    elif confidence >= adj_high and (
        diff_score >= DIFF_SCORE_ELEVATED or high_signal or intra_run_confirmed
    ):
        decision = "HIGH"
        reasons.append(
            f"High confidence ({confidence:.2f} >= {adj_high:.2f}) with supporting evidence"
        )
    # MEDIUM: moderate confidence or reproducible or strong signal
    elif (
        confidence >= adj_medium
        or reproducible
        or intra_run_confirmed
        or high_signal
        or diff_score >= DIFF_SCORE_ELEVATED
    ):
        decision = "MEDIUM"
        reasons.append(
            f"Medium confidence ({confidence:.2f} >= {adj_medium:.2f}) or confirmed/high signal"
        )
    # LOW: below medium threshold but still noteworthy (informational)
    elif confidence >= adj_low and (diff_score > 0 or len(signals_list) >= 1):
        decision = "LOW"
        reasons.append(f"Low confidence ({confidence:.2f} >= {adj_low:.2f}) with some signal")
    # DROP: insufficient evidence
    elif confidence < adj_low and not reproducible and not intra_run_confirmed and diff_score == 0:
        decision = "DROP"
        reasons.append(
            f"Below threshold ({confidence:.2f} < {adj_low:.2f}) with no supporting evidence"
        )
    # Fallback: if we have any signal at all, mark as LOW rather than DROP
    elif diff_score > 0 or len(signals_list) >= 1:
        decision = "LOW"
        reasons.append("Fallback: weak signal present")
    else:
        decision = "DROP"
        reasons.append("No sufficient evidence for classification")

    # Check for FP suppression patterns
    suppress_reason = ""
    mutated_status = int(diff.get("mutated_status", 0) or 0)
    original_status = int(diff.get("original_status", 0) or 0)

    # Status codes that indicate blocking (WAF, rate limit)
    block_status_codes = {403, 406, 418, 429}
    original_was_blocked = original_status in block_status_codes

    if mutated_status:
        is_fp, fp_category = _is_likely_false_positive(
            mutated_status, str(evidence.get("body_snippet", ""))
        )

        # If original was blocked but mutated is not, this is a potential bypass
        if original_was_blocked and not is_fp:
            reasons.append(
                f"Potential WAF bypass: original status {original_status} (blocked), "
                f"mutated status {mutated_status}"
            )
        elif is_fp:
            suppress_reason = f"Suppressed: matches {fp_category} false-positive pattern"
            reasons.append(suppress_reason)
            # Downgrade but don't fully drop if there's strong other evidence
            if decision == "HIGH" and not (cross_run_reproducible or reproducible):
                decision = "MEDIUM"
            elif decision in ("MEDIUM", "LOW") and not (
                cross_run_reproducible or reproducible or intra_run_confirmed
            ):
                decision = "DROP"

    return {
        "decision": decision,
        "reason": "; ".join(reasons) if reasons else "Default classification",
        "confidence_factors": confidence_factors,
        "suppress_reason": suppress_reason,
        "diff_score": diff_score,
        "diff_classification": diff_classification,
        "thresholds_used": {"low": adj_low, "medium": adj_medium, "high": adj_high},
    }


def annotate_finding_decisions(
    findings: list[dict[str, Any]], target_profile: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Annotate each finding with a decision, reason, and reportable flag.

    Args:
        findings: List of finding dicts to annotate.
        target_profile: Optional dict for dynamic threshold adjustment.

    Returns:
        List of findings with 'decision', 'reason', 'confidence_factors',
        'reportable', and 'suppress_reason' keys added.
    """
    annotated = []
    for item in findings:
        classification = classify_finding(item, target_profile)
        decision = classification["decision"]
        annotated.append(
            {
                **item,
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
    """Filter findings to only those that should appear in reports.

    Args:
        findings: List of annotated finding dicts with 'decision' keys.

    Returns:
        List of findings excluding those with 'DROP' decision.
    """
    return [item for item in findings if str(item.get("decision", "MEDIUM")).upper() != "DROP"]
