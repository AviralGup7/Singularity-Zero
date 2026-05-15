"""Response classification summaries and mutation strategy coverage."""

from typing import Any


def build_response_classification_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a summary of response classifications across all mutation findings."""
    classification_counts: dict[str, int] = {}
    status_transitions: dict[str, int] = {}
    similarity_scores: list[float] = []
    high_signal_endpoints: list[dict[str, Any]] = []
    total_mutations = 0
    total_changed = 0

    for finding in findings:
        signals = finding.get("signals", [])
        observations = finding.get("observations", [])
        total_mutations += len(observations) if observations else 1

        if finding.get("status_changed"):
            classification_counts["status_change"] = (
                classification_counts.get("status_change", 0) + 1
            )
            total_changed += 1
            orig = finding.get("original_status", 0)
            mut = finding.get("mutated_status", 0)
            if orig and mut:
                transition = f"{orig}->{mut}"
                status_transitions[transition] = status_transitions.get(transition, 0) + 1

        if finding.get("content_changed"):
            classification_counts["content_change"] = (
                classification_counts.get("content_change", 0) + 1
            )
            total_changed += 1

        if finding.get("redirect_changed"):
            classification_counts["redirect_change"] = (
                classification_counts.get("redirect_change", 0) + 1
            )
            total_changed += 1

        sim = finding.get("body_similarity")
        if sim is not None:
            similarity_scores.append(float(sim))

        if len(signals) >= 3 or finding.get("status_changed"):
            high_signal_endpoints.append(
                {
                    "url": finding.get("url", ""),
                    "signals": signals,
                    "status_changed": finding.get("status_changed", False),
                    "score": finding.get("score", 0),
                }
            )

    avg_similarity = round(sum(similarity_scores) / max(len(similarity_scores), 1), 3)

    return {
        "classification_counts": dict(sorted(classification_counts.items(), key=lambda x: -x[1])),
        "status_transitions": dict(sorted(status_transitions.items(), key=lambda x: -x[1])[:15]),
        "avg_body_similarity": avg_similarity,
        "total_mutations_tested": total_mutations,
        "total_changed_responses": total_changed,
        "change_rate": round(total_changed / max(total_mutations, 1), 3),
        "high_signal_endpoints": sorted(high_signal_endpoints, key=lambda x: -x.get("score", 0))[
            :20
        ],
    }


def build_mutation_strategy_coverage(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a summary of mutation strategy coverage and effectiveness."""
    strategy_counts: dict[str, int] = {}
    strategy_success: dict[str, int] = {}
    module_strategies: dict[str, set[str]] = {}

    for finding in findings:
        module = str(finding.get("module", "")).strip()
        observations = finding.get("observations", [])
        signals = finding.get("signals", [])

        for obs in observations or []:
            strategy = str(obs.get("strategy", obs.get("variant", ""))).strip()
            if not strategy:
                continue
            strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
            if (
                obs.get("status_changed")
                or obs.get("content_changed")
                or obs.get("body_similarity", 1.0) < 0.9
            ):
                strategy_success[strategy] = strategy_success.get(strategy, 0) + 1
            if module:
                module_strategies.setdefault(module, set()).add(strategy)

        for sig in signals:
            if "mutation" in str(sig).lower() or "probe" in str(sig).lower():
                strategy = str(sig).strip()
                strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
                if module:
                    module_strategies.setdefault(module, set()).add(strategy)

    strategy_rates: dict[str, float] = {}
    for strategy, count in strategy_counts.items():
        success = strategy_success.get(strategy, 0)
        strategy_rates[strategy] = round(success / max(count, 1), 2)

    underperforming = [
        {"strategy": s, "attempts": c, "success_rate": strategy_rates[s]}
        for s, c in strategy_counts.items()
        if c >= 3 and strategy_rates.get(s, 0) < 0.2
    ]

    return {
        "strategy_counts": dict(sorted(strategy_counts.items(), key=lambda x: -x[1])[:20]),
        "strategy_success_rates": dict(sorted(strategy_rates.items(), key=lambda x: x[1])[:15]),
        "coverage_by_module": {m: sorted(s) for m, s in sorted(module_strategies.items())},
        "underperforming_strategies": sorted(underperforming, key=lambda x: x["success_rate"]),
        "total_strategies_used": len(strategy_counts),
        "avg_success_rate": round(sum(strategy_rates.values()) / max(len(strategy_rates), 1), 2),
    }
