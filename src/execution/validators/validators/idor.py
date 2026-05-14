from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import (
    build_manual_hint,
    build_validator_result,
    classify_object_family,
    decode_candidate_value,
    normalized_confidence,
)
from src.core.models import ValidationResult
from src.core.plugins import register_plugin
from src.execution.validators.validators.shared import (
    IDOR_CONFIDENCE_BASE,
    IDOR_CONFIDENCE_CAP,
    to_validation_result,
)

VALIDATOR = "validator"


@register_plugin(VALIDATOR, "idor_candidates")
def validate_idor_candidates(
    analysis_results: dict[str, list[dict[str, Any]]],
    token_replay_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    replayable = bool((token_replay_summary or {}).get("replayable_locations"))
    findings: list[dict[str, Any]] = []

    for item in analysis_results.get("idor_candidate_finder", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        signals = sorted(
            {str(value).strip() for value in item.get("signals", []) if str(value).strip()}
        )
        query_keys = sorted(
            {
                str(value).strip().lower()
                for value in item.get("query_keys", [])
                if str(value).strip()
            }
        )
        comparison = item.get("comparison") if isinstance(item.get("comparison"), dict) else None
        multi_strategy = comparison.get("multi_strategy_confirmed", False) if comparison else False
        mutations_confirmed = comparison.get("mutations_confirmed", 0) if comparison else 0
        all_mutations_tested = comparison.get("all_mutations_tested", 0) if comparison else 0

        # Determine validation state with finer granularity
        if multi_strategy:
            validation_state = "multi_strategy_confirmed"
        elif comparison and comparison.get("body_similarity", 1.0) < 0.4:
            validation_state = "strong_response_similarity"
        elif comparison:
            validation_state = "response_similarity_match"
        else:
            validation_state = "heuristic_candidate"

        # Edge case: Check for self-referential endpoints (e.g., /users/me)
        is_self_reference = _is_self_referential_endpoint(url, query_keys)

        # Edge case: Check for public resource indicators
        is_public_resource = _is_public_resource(url, signals)

        # Edge case: Check for rate limiting signals that might affect confidence
        rate_limited = any("rate_limit" in s.lower() for s in signals)

        bonuses = [
            0.22 if multi_strategy else (0.18 if comparison else 0.0),
            0.03 if replayable else 0.0,
            0.06 if item.get("has_numeric_identifier") else -0.05,
            0.04 if mutations_confirmed >= 3 else (0.02 if mutations_confirmed >= 2 else 0.0),
            # Bonus for high mutation coverage (tested many, confirmed many)
            0.05 if all_mutations_tested >= 4 and mutations_confirmed >= 2 else 0.0,
            # Penalty for self-referential endpoints (less likely to be IDOR)
            -0.10 if is_self_reference else 0.0,
            # Penalty for public resources (expected to be accessible)
            -0.08 if is_public_resource else 0.0,
            # Penalty for rate-limited endpoints (may produce false positives)
            -0.05 if rate_limited else 0.0,
            # Bonus for object family specificity
            0.03
            if item.get("object_family")
            and item["object_family"] not in ("generic_object", "unknown")
            else 0.0,
        ]
        confidence = normalized_confidence(
            base=IDOR_CONFIDENCE_BASE,
            score=int(item.get("score", 0)),
            signals=signals,
            bonuses=bonuses,
            cap=IDOR_CONFIDENCE_CAP,
        )

        # Build edge case notes for transparency
        edge_case_notes = []
        if is_self_reference:
            edge_case_notes.append(
                "Endpoint appears to be self-referential (e.g., /me, /profile) — lower confidence as these are expected to return caller-owned data."
            )
        if is_public_resource:
            edge_case_notes.append(
                "Endpoint may serve public resources — accessibility may be intentional."
            )
        if rate_limited:
            edge_case_notes.append(
                "Rate limiting signals detected — response variations may be due to throttling rather than access control differences."
            )
        if all_mutations_tested >= 4 and mutations_confirmed >= 2:
            edge_case_notes.append(
                f"High mutation coverage: {mutations_confirmed}/{all_mutations_tested} mutations confirmed across multiple strategies."
            )

        findings.append(
            build_validator_result(
                module="idor_validation",
                category="idor",
                url=url,
                score=int(item.get("score", 0)),
                confidence=confidence,
                signals=signals,
                validation_state=validation_state,
                hint_message=build_manual_hint(
                    "idor", url, {"comparison": comparison or {}, "edge_cases": edge_case_notes}
                ),
                query_keys=query_keys,
                identifier_hints=_extract_identifiers(url, query_keys),
                comparison=comparison or {},
                object_family=item.get("object_family", classify_object_family(url)),
                edge_case_notes=edge_case_notes,
                is_self_reference=is_self_reference,
                is_public_resource=is_public_resource,
            )
        )

    findings.sort(
        key=lambda entry: (
            entry["validation_state"]
            not in (
                "multi_strategy_confirmed",
                "strong_response_similarity",
                "response_similarity_match",
            ),
            -entry["confidence"],
            -entry["score"],
            entry["url"],
        )
    )
    return findings[:20]


def _is_self_referential_endpoint(url: str, query_keys: list[str]) -> bool:
    """Check if the endpoint appears to be self-referential (returning caller's own data).

    Self-referential endpoints like /users/me, /profile, /my-account are less
    likely to be IDOR-vulnerable since they're designed to return the caller's data.
    """
    self_indicators = {
        "/me",
        "/me.json",
        "/me/",
        "/profile",
        "/profile/",
        "/my-",
        "/account",
        "/account/",
        "/self",
    }
    parsed = urlparse(url)
    path_lower = parsed.path.lower()

    # Check path for self-referential patterns
    if any(indicator in path_lower for indicator in self_indicators):
        return True

    # Check query keys for self-referential patterns
    self_keys = {"my_id", "self_id", "caller_id", "current_user"}
    if any(key in self_keys for key in query_keys):
        return True

    return False


def _is_public_resource(url: str, signals: list[str]) -> bool:
    """Check if the endpoint may serve public resources.

    Public resources like /products, /articles, /posts are expected to be
    accessible and are less likely to represent IDOR vulnerabilities.
    """
    public_indicators = {
        "/products",
        "/articles",
        "/posts",
        "/blog",
        "/news",
        "/public",
        "/catalog",
        "/listings",
    }
    path_lower = urlparse(url).path.lower()

    if any(indicator in path_lower for indicator in public_indicators):
        return True

    # Check for public object family
    public_families = {"public_article", "public_product", "public_post"}
    if any(f"object_family:{family}" in signals for family in public_families):
        return True

    return False


@register_plugin(VALIDATOR, "promote_idor_evidence")
def promote_evidence_backed_results(idor_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    promoted = []
    for item in idor_results:
        if item.get("validation_state") not in (
            "multi_strategy_confirmed",
            "response_similarity_match",
        ):
            continue
        comparison = item.get("comparison", {})
        severity = (
            "critical" if item.get("validation_state") == "multi_strategy_confirmed" else "high"
        )
        title = (
            "Multi-strategy confirmed IDOR"
            if item.get("validation_state") == "multi_strategy_confirmed"
            else "Evidence-backed IDOR candidate"
        )
        promoted.append(
            {
                "title": title,
                "severity": severity,
                "url": item.get("url", ""),
                "confidence": item.get("confidence", 0),
                "evidence": {
                    "shared_key_fields": comparison.get("shared_key_fields", []),
                    "body_similarity": comparison.get("body_similarity"),
                    "mutated_url": comparison.get("mutated_url", ""),
                    "mutations_tested": comparison.get("all_mutations_tested", 0),
                    "mutations_confirmed": comparison.get("mutations_confirmed", 0),
                    "multi_strategy": comparison.get("multi_strategy_confirmed", False),
                },
            }
        )
    return promoted[:10]


def _extract_identifiers(url: str, query_keys: list[str]) -> list[str]:
    identifiers = []
    for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        normalized_key = key.strip().lower()
        if normalized_key in query_keys and value.strip():
            identifiers.append(f"{normalized_key}={decode_candidate_value(value.strip())}")
    return identifiers[:8]


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    token_replay = context.get("token_replay") if isinstance(context, dict) else None
    analysis_results = {"idor_candidate_finder": [target]}
    items = validate_idor_candidates(analysis_results, token_replay)
    if not items:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "failed"}, validator="idor", category="idor"
        )
    return to_validation_result(items[0], validator="idor", category="idor")
