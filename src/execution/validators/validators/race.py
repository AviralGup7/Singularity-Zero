"""Race condition / TOCTOU validator (R7).

Sends N concurrent requests to a state-changing endpoint and analyzes the
responses for inconsistent results that suggest a race condition or limit
overflow (e.g. double-spending, double-redeeming, balance checks that race
with debits).

The validator is offline-friendly: callers supply a ``runner`` callable
that performs a single request and returns a ``{"status_code": int,
"body": str, "headers": dict, "duration": float}`` dict. The validator
takes care of concurrency and analysis.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from src.execution.validators.config.scoring_config import ScoringConfig
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.shared import (
    bounded_confidence,
    to_validation_result,
)
from src.infrastructure.execution_engine.shared_pool import get_shared_executor

logger = logging.getLogger(__name__)


def _summarize_responses(responses: list[dict[str, Any]]) -> dict[str, Any]:
    statuses: list[int] = []
    success_count = 0
    failure_count = 0
    bodies: list[str] = []
    for response in responses:
        status = int(response.get("status_code", 0) or 0)
        statuses.append(status)
        bodies.append(str(response.get("body", "")))
        if 200 <= status < 300:
            success_count += 1
        elif status:
            failure_count += 1
    return {
        "statuses": statuses,
        "success_count": success_count,
        "failure_count": failure_count,
        "bodies": bodies,
    }


def _looks_like_duplicate_success(responses: list[dict[str, Any]]) -> bool:
    """Heuristic: at least 2 successful 2xx responses with the same body."""
    success_pairs: list[tuple[int, str]] = []
    for response in responses:
        status = int(response.get("status_code", 0) or 0)
        if 200 <= status < 300:
            success_pairs.append((status, str(response.get("body", ""))))
    seen: dict[tuple[int, str], int] = {}
    for pair in success_pairs:
        seen[pair] = seen.get(pair, 0) + 1
    return any(count >= 2 for count in seen.values())


def _inconsistent_responses(responses: list[dict[str, Any]]) -> bool:
    """Heuristic: at least one 2xx and one 5xx/error response."""
    statuses = [int(r.get("status_code", 0) or 0) for r in responses]
    if not statuses:
        return False
    has_2xx = any(200 <= s < 300 for s in statuses)
    has_5xx = any(s >= 500 for s in statuses)
    has_4xx = any(400 <= s < 500 for s in statuses)
    return has_2xx and (has_4xx or has_5xx)


def evaluate_race_condition(
    *,
    target_url: str,
    responses: list[dict[str, Any]],
    scoring: ScoringConfig,
    expected_concurrency: int = 5,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Evaluate a race-condition probe.

    Args:
        target_url: The URL tested.
        responses: Per-request response dicts from the concurrent probe.
        scoring: Per-validator ``ScoringConfig``.
        expected_concurrency: Number of concurrent requests expected.
        in_scope: Whether the target endpoint is in scope.

    Returns:
        Dict with status/confidence/signals/evidence/bonuses.
    """
    summary = _summarize_responses(responses)
    duplicate = _looks_like_duplicate_success(responses)
    inconsistent = _inconsistent_responses(responses)

    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []

    if duplicate:
        signals.append("duplicate_success")
        bonuses.append(0.18)
        notes.append("Two or more concurrent requests returned identical 2xx responses.")
    if inconsistent:
        signals.append("inconsistent_response")
        bonuses.append(0.10)
        notes.append("Mixed success/failure responses under concurrent load.")
    if summary["success_count"] >= expected_concurrency:
        signals.append("all_concurrent_succeeded")
        bonuses.append(0.05)
    if len(responses) < expected_concurrency:
        notes.append(f"Only {len(responses)} of {expected_concurrency} responses captured.")

    if signals and in_scope and (duplicate or inconsistent):
        status = ValidationStatus.CONFIRMED.value
    elif signals and in_scope:
        status = ValidationStatus.HEURISTIC.value
    elif signals:
        status = ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    confidence = bounded_confidence(
        base=scoring.base,
        cap=scoring.cap,
        bonuses=bonuses,
    )
    evidence = {
        "concurrency": len(responses),
        "expected_concurrency": expected_concurrency,
        "summary": {key: value for key, value in summary.items() if key != "bodies"},
        "duplicate_success": duplicate,
        "inconsistent_response": inconsistent,
        "signals": signals,
        "notes": notes,
    }
    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "evidence": evidence,
        "bonuses": bonuses,
    }


def run_race_probe(
    *,
    runner: Callable[[], dict[str, Any]],
    concurrency: int = 5,
) -> list[dict[str, Any]]:
    """Run ``runner`` ``concurrency`` times in parallel and return responses."""
    if concurrency <= 0:
        return []
    responses: list[dict[str, Any]] = []
    executor = get_shared_executor()
    futures = [executor.submit(runner) for _ in range(concurrency)]
    for future in futures:
        try:
            responses.append(future.result(timeout=30) or {})
        except Exception as exc:  # noqa: BLE001
            logger.debug("race probe future failed: %s", exc)
            responses.append({"status_code": 0, "body": "", "error": str(exc)})
    return responses


def validate_race_condition(
    *,
    target_url: str,
    responses: list[dict[str, Any]],
    scoring: ScoringConfig,
    expected_concurrency: int = 5,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Validate a race condition probe and return a result dict."""
    evaluation = evaluate_race_condition(
        target_url=target_url,
        responses=responses,
        scoring=scoring,
        expected_concurrency=expected_concurrency,
        in_scope=in_scope,
    )
    item = {
        "url": target_url,
        "status": evaluation["status"],
        "confidence": evaluation["confidence"],
        "in_scope": in_scope,
        "scope_reason": "scope_evaluated" if in_scope else "scope_unavailable_or_out_of_scope",
        "evidence": evaluation["evidence"],
    }
    return to_validation_result(
        item, validator="race_condition", category="race_condition"
    ).__dict__


def validate(target: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """R1 facade entry point matching the ``Validator`` Protocol.

    Active probing is performed by the engine ``RaceConditionValidator``.
    The facade returns a passive evaluation when ``responses`` are
    present in ``context`` (e.g. from a prior concurrent run).
    """
    from src.execution.validators.config.scoring_config import (
        DEFAULT_SCORING_CONFIG,
    )

    target_url = str(target.get("url", ""))
    responses = list(context.get("responses") or [])
    concurrency = int(context.get("race_concurrency", 5) or 5)
    if not responses:
        return to_validation_result(
            {
                "url": target_url,
                "status": ValidationStatus.INCONCLUSIVE.value,
                "confidence": 0.0,
                "in_scope": bool(context.get("in_scope", True)),
                "scope_reason": "no_responses",
            },
            validator="race_condition",
            category="race_condition",
        ).__dict__
    return validate_race_condition(
        target_url=target_url,
        responses=responses,
        scoring=DEFAULT_SCORING_CONFIG["race_condition"],
        expected_concurrency=concurrency,
        in_scope=bool(context.get("in_scope", True)),
    )
