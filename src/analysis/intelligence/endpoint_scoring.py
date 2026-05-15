"""Scoring, reasoning, and cross-endpoint correlation helpers for endpoint intelligence.

Contains helper functions for response diff weighting, parameter sensitivity
scoring, endpoint reasoning generation, and cross-endpoint correlation.
Extracted from endpoint_intelligence.py for better separation of concerns.
"""

from typing import Any


def _response_diff_weight(diff: dict[str, Any]) -> int:
    """Compute weighted score for response diff significance.

    Higher weights indicate more meaningful behavioral changes that are
    more likely to represent actual vulnerabilities rather than noise.
    """
    weight = 0
    if diff.get("status_changed"):
        weight += 5
        # Status changes to error codes are less significant than to success
        mutated_status = diff.get("mutated_status", 0)
        original_status = diff.get("original_status", 0)
        if isinstance(mutated_status, int) and isinstance(original_status, int):
            if original_status < 400 and mutated_status >= 500:
                weight += 2  # Server error indicates injection potential
            elif original_status < 400 and mutated_status == 403:
                weight += 3  # Forbidden change indicates access control boundary
            elif original_status >= 400 and mutated_status < 400:
                weight += 4  # Error to success is highly significant
    if diff.get("redirect_changed"):
        weight += 4
        # Cross-host redirect changes are more significant
        if diff.get("classification") == "include":
            weight += 2
    if diff.get("content_changed"):
        weight += 3
    similarity = float(diff.get("body_similarity", 1.0) or 1.0)
    if similarity < 0.3:
        weight += 8
    elif similarity < 0.5:
        weight += 5
    elif similarity < 0.7:
        weight += 2
    if diff.get("changed"):
        weight += 2
    # Bonus for structured diff availability (JSON field changes are more actionable)
    if diff.get("structured_diff_available"):
        new_fields = diff.get("new_fields", [])
        missing_fields = diff.get("missing_fields", [])
        if new_fields or missing_fields:
            weight += min(len(new_fields) + len(missing_fields), 4)
    return weight


def _parameter_sensitivity_score(suggestions: list[dict[str, Any]]) -> int:
    """Score parameter sensitivity based on parameter names and types.

    Higher scores indicate endpoints with more security-critical parameters.
    Accumulates scores across all parameters (not just the max) to properly
    reflect endpoints with multiple sensitive parameter types.
    """
    score = 0
    # ID-type parameters (IDOR, object reference exposure)
    id_params = {
        "id",
        "user_id",
        "account_id",
        "tenant_id",
        "org_id",
        "project_id",
        "workspace_id",
        "group_id",
        "team_id",
        "company_id",
    }
    for item in suggestions or []:
        parameter = str(item.get("parameter", "")).lower()
        if parameter in id_params or parameter.endswith("_id"):
            score += 2  # Accumulate: each ID param adds 2
        # Auth/session parameters
        if parameter in {"token", "session", "jwt", "state", "nonce", "code", "authorization"}:
            score += 3  # Accumulate: each auth param adds 3
        # Redirect/URL sink parameters (SSRF, open redirect)
        if parameter in {
            "callback",
            "redirect",
            "return",
            "return_to",
            "url",
            "uri",
            "dest",
            "destination",
            "next",
            "continue",
            "target",
            "forward",
            "redir",
        }:
            score += 3  # Accumulate: each redirect param adds 3
        # File/path parameters (LFI, path traversal)
        if parameter in {
            "file",
            "path",
            "document",
            "attachment",
            "download",
            "include",
            "page",
            "template",
        }:
            score += 2  # Accumulate: each file param adds 2
        # Payment/financial parameters
        if parameter in {
            "amount",
            "price",
            "quantity",
            "discount",
            "coupon",
            "currency",
            "payment_method",
            "card",
        }:
            score += 3  # Accumulate: each payment param adds 3
        # Role/permission parameters (privilege escalation)
        if parameter in {
            "role",
            "permission",
            "scope",
            "access_level",
            "privilege",
            "admin",
            "is_admin",
        }:
            score += 3  # Accumulate: each role param adds 3
        # Search/filter parameters (injection, data exposure)
        if parameter in {"search", "query", "filter", "sort", "order", "field", "fields", "select"}:
            score += 1  # Accumulate: each filter param adds 1
    # Cap total score to prevent runaway values
    return min(score, 12)


def _build_endpoint_reasoning(
    record: dict[str, Any], multi_signal: set[str], signal_count: int, threat_surface_score: float
) -> str:
    """Build a human-readable explanation of why this endpoint is high-priority.

    Provides context-aware reasoning that combines signal analysis, evidence
    depth, and attack chain potential into a clear explanation.
    """
    parts: list[str] = []

    # Primary reason based on strongest signals
    if "confirmed" in record["signals"]:
        parts.append("This endpoint has confirmed behavioral changes under mutation testing.")
    elif "reproducible" in record["signals"]:
        parts.append(
            "This endpoint shows reproducible response changes under controlled parameter mutation."
        )

    # Multi-signal correlation reasoning
    if len(multi_signal) >= 3:
        parts.append(
            f"High signal diversity ({len(multi_signal)} overlapping signal categories: {', '.join(sorted(multi_signal)[:4])}) suggests a complex attack surface."
        )
    elif len(multi_signal) >= 2:
        parts.append(
            f"Multiple signal categories overlap ({', '.join(sorted(multi_signal)[:3])}), increasing the likelihood of exploitable behavior."
        )

    # Trust boundary reasoning
    if record["trust_boundary"] == "cross-host":
        parts.append(
            "Cross-host trust boundary detected — the endpoint interacts with resources across different trust zones."
        )

    # Evidence depth reasoning
    if len(record["evidence_modules"]) >= 5:
        parts.append(
            f"Deep evidence correlation ({len(record['evidence_modules'])} independent analysis modules flagged this endpoint)."
        )
    elif len(record["evidence_modules"]) >= 3:
        parts.append(
            f"Multiple analysis modules ({len(record['evidence_modules'])}) independently identified signals on this endpoint."
        )

    # Flow complexity reasoning
    if record["flow_labels"]:
        parts.append(
            f"Part of {len(record['flow_labels'])} detected workflow(s): {', '.join(sorted(record['flow_labels'])[:3])}."
        )

    # Parameter sensitivity reasoning
    if record["parameter_sensitivity"] >= 4:
        parts.append(
            "High parameter sensitivity indicates complex input handling that may have edge cases."
        )

    # Resource group reasoning
    if record["resource_group"] in {"users", "accounts", "orders", "devices", "payments"}:
        parts.append(
            f"High-value resource group ({record['resource_group']}) — unauthorized access could expose sensitive data."
        )

    # Schema marker reasoning
    if record["schema_markers"]:
        sensitive_markers = [
            m
            for m in record["schema_markers"]
            if any(k in m for k in ("sensitive", "role", "admin", "payment"))
        ]
        if sensitive_markers:
            parts.append(
                f"Schema analysis flagged sensitive markers: {', '.join(sensitive_markers[:3])}."
            )

    # Threat surface summary
    if threat_surface_score >= 0.7:
        parts.append(f"Overall threat surface score: {threat_surface_score:.2f} (high).")
    elif threat_surface_score >= 0.4:
        parts.append(f"Overall threat surface score: {threat_surface_score:.2f} (moderate).")

    return (
        " ".join(parts)
        if parts
        else f"Endpoint flagged with {signal_count} signal(s) across {len(record['evidence_modules'])} analysis module(s)."
    )


def _apply_cross_endpoint_correlation(enriched: list[dict[str, Any]]) -> None:
    """Apply cross-endpoint correlation to find related endpoints with complementary signals.

    Groups endpoints by resource group and host, then identifies patterns where
    related endpoints show complementary security signals (e.g., one endpoint
    shows IDOR while another shows auth bypass on the same resource).

    Adds 'cross_endpoint_correlations' and 'correlation_score_bonus' to each item.
    """
    # Group by resource group
    resource_groups: dict[str, list[dict[str, Any]]] = {}
    host_groups: dict[str, list[dict[str, Any]]] = {}
    for item in enriched:
        rg = str(item.get("resource_group", "")).strip()
        host = str(item.get("host", "")).strip()
        if rg:
            resource_groups.setdefault(rg, []).append(item)
        if host:
            host_groups.setdefault(host, []).append(item)

    # High-value signal combinations that indicate attack chains
    attack_chain_signals = {
        "idor": {"access_control", "schema", "response_diff"},
        "auth_bypass_chain": {"auth", "access_control", "session"},
        "data_exfil_chain": {"sensitive_data", "pagination", "filter_diff"},
        "ssrf_chain": {"ssrf", "redirect", "response_diff"},
        "business_logic_chain": {"business_logic", "flow_transition", "reproducible"},
    }

    for item in enriched:
        correlations: list[dict[str, Any]] = []
        correlation_bonus = 0
        item_signals = set(item.get("signals", []))
        item_key = str(item.get("endpoint_key", ""))
        item_rg = str(item.get("resource_group", "")).strip()
        item_host = str(item.get("host", "")).strip()

        # Check resource group correlations
        if item_rg and item_rg in resource_groups:
            for peer in resource_groups[item_rg]:
                peer_key = str(peer.get("endpoint_key", ""))
                if peer_key == item_key:
                    continue
                peer_signals = set(peer.get("signals", []))
                # Find complementary signals (signals in peer but not in item)
                complementary = peer_signals - item_signals
                shared = peer_signals & item_signals
                if complementary and shared:
                    correlations.append(
                        {
                            "type": "resource_group",
                            "peer_url": peer.get("url", ""),
                            "peer_endpoint_key": peer_key,
                            "shared_signals": sorted(shared),
                            "complementary_signals": sorted(complementary),
                            "peer_decision": peer.get("decision", "MEDIUM"),
                            "peer_score": peer.get("score", 0),
                        }
                    )
                    # Bonus for complementary high-value signals
                    if peer.get("decision") == "HIGH":
                        correlation_bonus += 3

        # Check host-level correlations (same origin, different resources)
        if item_host and item_host in host_groups:
            for peer in host_groups[item_host]:
                peer_key = str(peer.get("endpoint_key", ""))
                if peer_key == item_key:
                    continue
                peer_rg = str(peer.get("resource_group", "")).strip()
                # Only correlate across different resource groups on same host
                if peer_rg and peer_rg == item_rg:
                    continue
                peer_signals = set(peer.get("signals", []))
                # Check for attack chain patterns
                for chain_name, chain_signals in attack_chain_signals.items():
                    if chain_signals & item_signals and chain_signals & peer_signals:
                        correlations.append(
                            {
                                "type": "attack_chain",
                                "chain_name": chain_name,
                                "peer_url": peer.get("url", ""),
                                "peer_endpoint_key": peer_key,
                                "chain_signals_present": sorted(
                                    chain_signals & (item_signals | peer_signals)
                                ),
                            }
                        )
                        correlation_bonus += 2
                        break  # One chain match per peer is enough

        # Cap correlations to avoid bloating output
        item["cross_endpoint_correlations"] = correlations[:5]
        item["correlation_score_bonus"] = correlation_bonus
        if correlation_bonus > 0:
            item["score"] = item.get("score", 0) + correlation_bonus
            # Update score breakdown
            breakdown = item.get("score_breakdown", [])
            if isinstance(breakdown, list):
                breakdown.append(f"cross_endpoint_correlation:{correlation_bonus}")
