"""Endpoint intelligence scoring and enrichment.

Applies scoring, confidence calculation, threat surface assessment,
and decision classification to endpoint intelligence records.
"""

from typing import Any
from urllib.parse import urlparse

from src.analysis.intelligence.decision_engine import classify_finding
from src.analysis.intelligence.endpoint_scoring import (
    _build_endpoint_reasoning,
    _response_diff_weight,
)


def enrich_and_score_endpoints(
    endpoint_map: dict[str, dict[str, Any]],
    validation_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """Enrich endpoint records with scoring, confidence, and decision classification."""
    enriched = []
    for record in endpoint_map.values():
        record["auth_contexts"].update(_inferred_auth_contexts(record))
        signal_count = len(record["signals"])

        # Multi-signal correlation
        multi_signal = {
            "auth",
            "redirect",
            "ssrf",
            "token",
            "xss",
            "access_control",
            "session",
            "business_logic",
            "payment",
            "behavior",
            "response_diff",
            "anomaly",
            "schema",
            "reproducible",
            "confirmed",
            "intra_run_confirmed",
            "cross_run_reproducible",
        } & record["signals"]

        for signal in multi_signal:
            partners = sorted(multi_signal - {signal})
            if partners:
                record["signal_cooccurrence"][signal] = partners

        all_signals_sorted = sorted(record["signals"])
        if len(all_signals_sorted) >= 2:
            for sig in all_signals_sorted:
                if sig not in record["signal_cooccurrence"]:
                    record["signal_cooccurrence"][sig] = [s for s in all_signals_sorted if s != sig]

        # Score calculation
        score = _calculate_score(record, multi_signal, signal_count)

        # Evidence confidence
        evidence_confidence = _calculate_confidence(
            record, multi_signal, signal_count, validation_results
        )

        # Threat surface score
        threat_surface_score = _calculate_threat_surface(record, multi_signal)

        # Score breakdown for transparency
        score_breakdown = _build_score_breakdown(record, multi_signal, signal_count)

        # Finding reasoning
        finding_reasoning = _build_endpoint_reasoning(
            record, multi_signal, signal_count, threat_surface_score
        )

        # Decision classification
        decision_result = classify_finding(
            {
                "severity": "high"
                if score >= 22 or record["trust_boundary"] == "cross-host"
                else "medium"
                if score >= 12
                else "low",
                "confidence": evidence_confidence,
                "combined_signal": " + ".join(sorted(multi_signal)),
                "evidence": {
                    "reproducible": "reproducible" in record["signals"]
                    or "confirmed" in record["signals"],
                    "confirmed": "confirmed" in record["signals"],
                    "trust_boundary": record["trust_boundary"],
                    "diff": record["response_diff"] or {},
                    "score_breakdown": score_breakdown,
                    "evidence_module_count": len(record["evidence_modules"]),
                    "threat_surface_score": threat_surface_score,
                },
            }
        )
        decision = (
            decision_result["decision"] if isinstance(decision_result, dict) else decision_result
        )

        host = urlparse(record["url"]).netloc.lower()

        enriched.append(
            {
                "url": record["url"],
                "endpoint_key": record["endpoint_key"],
                "endpoint_base_key": record["endpoint_base_key"],
                "endpoint_type": record["endpoint_type"],
                "host": host,
                "score": score,
                "signal_count": signal_count,
                "signals": sorted(record["signals"]),
                "multi_signal_priority": sorted(multi_signal),
                "flow_labels": sorted(record["flow_labels"]),
                "evidence_modules": sorted(record["evidence_modules"]),
                "payload_suggestions": record["payload_suggestions"][:6],
                "attack_hints": record["attack_hints"][:4],
                "response_snapshot": record["response_snapshot"],
                "response_diff": record["response_diff"],
                "trust_boundary": record["trust_boundary"],
                "parameter_sensitivity": record["parameter_sensitivity"],
                "flow_score": record["flow_score"],
                "normalized_score": record["normalized_score"],
                "signal_cooccurrence": record["signal_cooccurrence"],
                "evidence_confidence": evidence_confidence,
                "threat_surface_score": threat_surface_score,
                "finding_reasoning": finding_reasoning,
                "resource_group": record["resource_group"],
                "schema_markers": record["schema_markers"][:6],
                "query_parameters": sorted(record["query_parameters"]),
                "auth_contexts": sorted(record["auth_contexts"]),
                "decision": decision,
                "decision_reason": decision_result.get("reason", "")
                if isinstance(decision_result, dict)
                else "",
                "confidence_factors": decision_result.get("confidence_factors", [])
                if isinstance(decision_result, dict)
                else [],
                "score_breakdown": score_breakdown,
                "reason": finding_reasoning,
            }
        )

    return [item for item in enriched if item["decision"] != "DROP"]


def _calculate_score(record: dict[str, Any], multi_signal: set[str], signal_count: int) -> int:
    """Calculate endpoint intelligence score."""
    score = int(record["base_score"])

    signal_weights = {
        "confirmed": 6,
        "reproducible": 4,
        "trust_boundary_shift": 5,
        "access_control": 4,
        "ssrf": 4,
        "xss": 3,
        "session": 3,
        "payment": 3,
        "behavior": 3,
        "business_logic": 2,
        "auth": 2,
        "token": 2,
        "redirect": 2,
        "response_diff": 2,
        "anomaly": 1,
        "schema": 1,
        "flow_transition": 2,
        "intra_run_confirmed": 5,
        "cross_run_reproducible": 4,
    }
    weighted_signal_score = sum(signal_weights.get(sig, 1) for sig in record["signals"])
    score += signal_count * 3 + weighted_signal_score

    # Multi-signal bonuses
    if len(multi_signal) >= 2:
        score += 8
    if len(multi_signal) >= 3:
        score += 10
    if len(multi_signal) >= 4:
        score += 6
    if len(multi_signal) >= 5:
        score += 4

    # Dangerous signal combinations
    dangerous_combos = [
        ({"ssrf", "access_control"}, 6),
        ({"ssrf", "auth"}, 5),
        ({"xss", "session"}, 5),
        ({"access_control", "payment"}, 6),
        ({"auth", "token"}, 4),
        ({"business_logic", "payment"}, 5),
        ({"behavior", "access_control"}, 4),
        ({"confirmed", "ssrf"}, 5),
        ({"confirmed", "access_control"}, 5),
        ({"confirmed", "xss"}, 4),
        ({"trust_boundary_shift", "auth"}, 6),
        ({"trust_boundary_shift", "ssrf"}, 6),
    ]
    for combo_signals, combo_bonus in dangerous_combos:
        if combo_signals.issubset(record["signals"]):
            score += combo_bonus

    if record["flow_labels"]:
        score += 5 + min(len(record["flow_labels"]), 2) * 2
    score += int(record["flow_score"])
    if record["response_diff"]:
        score += _response_diff_weight(record["response_diff"])
    if record["response_snapshot"] and "jwt_like_token" in record["response_snapshot"].get(
        "key_patterns", []
    ):
        score += 5
    if "trust_boundary_shift" in record["signals"]:
        score += 12
        record["trust_boundary"] = "cross-host"
    if "confirmed" in record["signals"]:
        score += 10
    elif "reproducible" in record["signals"]:
        score += 5
    score += int(record["parameter_sensitivity"])
    score += int(record["normalized_score"] // 20)
    if record["endpoint_type"] == "AUTH":
        score += 2
    if record["resource_group"] in {"users", "accounts", "orders", "devices"}:
        score += 3
    if "payment" in record["signals"]:
        score += 4
    if record["schema_markers"]:
        score += min(len(record["schema_markers"]), 4)
    if "active_probe" in record["signals"]:
        score += 3
    if any(sig.startswith("severity:") for sig in record["signals"]):
        score += 2

    return score


def _calculate_confidence(
    record: dict[str, Any],
    multi_signal: set[str],
    signal_count: int,
    validation_results: dict[str, Any],
) -> float:
    """Calculate evidence confidence for an endpoint."""
    evidence_confidence = 0.30

    if "stable_diff" in record["signals"]:
        evidence_confidence += 0.12
    if "reproducible" in record["signals"]:
        evidence_confidence += 0.14
    if "confirmed" in record["signals"]:
        evidence_confidence += 0.14
    if "intra_run_confirmed" in record["signals"]:
        evidence_confidence += 0.12
    if "cross_run_reproducible" in record["signals"]:
        evidence_confidence += 0.10
    if (
        record["response_diff"]
        and float(record["response_diff"].get("body_similarity", 1.0) or 1.0) < 0.3
    ):
        evidence_confidence += 0.10
    if record["trust_boundary"] == "cross-host":
        evidence_confidence += 0.12
    if len(multi_signal) >= 2:
        evidence_confidence += 0.08
    if len(multi_signal) >= 3:
        evidence_confidence += 0.06
    if len(record["evidence_modules"]) >= 3:
        evidence_confidence += 0.06
    if len(record["evidence_modules"]) >= 5:
        evidence_confidence += 0.04
    if record["parameter_sensitivity"] >= 4:
        evidence_confidence += 0.04
    if record["resource_group"] in {"users", "accounts", "orders", "devices", "payments"}:
        evidence_confidence += 0.03

    # Validation-confirmed bonus
    validated_keys = {
        str(v.get("endpoint_key", ""))
        for v_results in validation_results.values()
        for v in v_results
        if v.get("validation_state")
        in (
            "potential_idor",
            "response_similarity_match",
            "observed_similarity_match",
            "auth_bypass_indicator",
            "multi_strategy_confirmed",
        )
    }
    if record["endpoint_key"] in validated_keys:
        evidence_confidence += 0.10

    # Penalties
    if (
        "anomaly" in record["signals"]
        and "confirmed" not in record["signals"]
        and "reproducible" not in record["signals"]
        and "intra_run_confirmed" not in record["signals"]
    ):
        evidence_confidence -= 0.05
    if signal_count <= 1 and record["base_score"] < 5:
        evidence_confidence -= 0.08

    return round(max(0.10, min(evidence_confidence, 0.97)), 2)


def _calculate_threat_surface(record: dict[str, Any], multi_signal: set[str]) -> float:
    """Calculate threat surface score."""
    threat_surface_score = 0.0
    threat_surface_score += min(len(multi_signal) * 0.15, 0.45)
    threat_surface_score += min(len(record["evidence_modules"]) * 0.08, 0.32)
    threat_surface_score += min(record["parameter_sensitivity"] * 0.05, 0.20)
    if record["flow_labels"]:
        threat_surface_score += min(len(record["flow_labels"]) * 0.06, 0.18)
    if "confirmed" in record["signals"]:
        threat_surface_score += 0.15
    if record["trust_boundary"] == "cross-host":
        threat_surface_score += 0.12
    return float(round(min(threat_surface_score, 1.0), 2))


def _build_score_breakdown(
    record: dict[str, Any], multi_signal: set[str], signal_count: int
) -> list[str]:
    """Build human-readable score breakdown."""
    score_breakdown = []
    if int(record["base_score"]) > 0:
        score_breakdown.append(f"base:{record['base_score']}")
    if signal_count > 0:
        score_breakdown.append(f"signals:{signal_count * 3}")
    if len(multi_signal) >= 2:
        multi_bonus = 8
        if len(multi_signal) >= 3:
            multi_bonus += 2
        if len(multi_signal) >= 4:
            multi_bonus += 6
        if len(multi_signal) >= 5:
            multi_bonus += 4
        score_breakdown.append(f"multi_signal:{multi_bonus}")
    if record["flow_labels"]:
        score_breakdown.append(f"flow:{5 + min(len(record['flow_labels']), 2) * 2}")
    if "trust_boundary_shift" in record["signals"]:
        score_breakdown.append("trust_boundary:12")
    if "confirmed" in record["signals"]:
        score_breakdown.append("confirmed:10")
    elif "reproducible" in record["signals"]:
        score_breakdown.append("reproducible:5")
    if record["parameter_sensitivity"] > 0:
        score_breakdown.append(f"param_sensitivity:{record['parameter_sensitivity']}")
    if record["normalized_score"] > 0:
        score_breakdown.append(f"normalized_bonus:{int(record['normalized_score'] // 20)}")
    if record["endpoint_type"] == "AUTH":
        score_breakdown.append("auth_endpoint:2")
    if record["resource_group"] in {"users", "accounts", "orders", "devices"}:
        score_breakdown.append("resource_group:3")
    if "payment" in record["signals"]:
        score_breakdown.append("payment:4")
    if record["schema_markers"]:
        score_breakdown.append(f"schema:{min(len(record['schema_markers']), 4)}")
    if len(record["evidence_modules"]) >= 3:
        score_breakdown.append(
            f"evidence_correlation:{0.06 + (0.04 if len(record['evidence_modules']) >= 5 else 0)}"
        )
    if record["parameter_sensitivity"] >= 4:
        score_breakdown.append("param_sensitivity_bonus:0.04")
    if record["resource_group"] in {"users", "accounts", "orders", "devices", "payments"}:
        score_breakdown.append("resource_group_bonus:0.03")
    return score_breakdown


def _inferred_auth_contexts(record: dict[str, Any]) -> set[str]:
    """Infer additional auth contexts from signals and schema markers."""
    contexts = {
        str(value).strip().lower()
        for value in record.get("auth_contexts", set())
        if str(value).strip()
    }
    signals = {
        str(value).strip().lower() for value in record.get("signals", set()) if str(value).strip()
    }
    schema_markers = {
        str(value).strip().lower()
        for value in record.get("schema_markers", [])
        if str(value).strip()
    }

    if record.get("endpoint_type") == "AUTH":
        contexts.add("auth_flow")
    if "unauth" in signals:
        contexts.add("public")
    if {"auth", "session", "token", "access_control", "behavior", "auth_tamper"} & signals:
        contexts.add("authenticated")
    if "privileged" in contexts or any(
        "admin" in marker or "role_field:" in marker for marker in schema_markers
    ):
        contexts.add("privileged")
    if not contexts:
        contexts.add(
            "public" if record.get("endpoint_type") in {"GENERAL", "STATIC"} else "authenticated"
        )
    return contexts
