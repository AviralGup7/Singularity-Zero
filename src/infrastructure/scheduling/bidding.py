"""Multi-objective bidding primitives for scan scheduling.

The scheduler uses one comparable bid score across URL targets, distributed
queue jobs, and in-process execution tasks. Higher scores are dispatched
earlier. Inputs are intentionally tolerant: producers can pass explicit
metadata, while legacy integer priorities still map into a useful bid.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Protocol


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _scale_10(value: Any, default: float = 0.0) -> float:
    raw = _as_float(value, default)
    if raw > 1.0:
        return max(0.0, raw / 10.0)
    return _clamp(raw)


def _first_present(*sources: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    for source in sources:
        for key in keys:
            if key in source and source[key] is not None:
                return source[key]
    return default


def _nested_sources(payload: dict[str, Any], metadata: dict[str, Any]) -> list[dict[str, Any]]:
    nested: list[dict[str, Any]] = [metadata, payload]
    for key in ("metadata", "scheduling", "bid", "sla", "payload"):
        value = payload.get(key)
        if isinstance(value, dict):
            nested.append(value)
    return nested


@dataclass(frozen=True)
class BidWeights:
    """Weights for each dispatch objective."""

    priority: float = 0.85
    exploitability: float = 2.3
    business_criticality: float = 1.7
    analyst_sla: float = 1.5
    historical_velocity: float = 1.0
    age: float = 0.35
    resource_contention: float = 1.2
    bloom_mesh_saturation: float = 1.1
    retries: float = 0.2


@dataclass(frozen=True)
class MultiObjectiveBid:
    """Comparable dispatch bid for one unit of work."""

    score: float
    priority: float
    exploitability: float
    business_criticality: float
    analyst_sla_urgency: float
    historical_velocity: float
    resource_contention: float
    bloom_mesh_saturation: float
    age_seconds: float
    retry_penalty: float = 0.0
    resource_types: tuple[str, ...] = ("default",)
    components: dict[str, float] = field(default_factory=dict)

    def redis_score(self) -> float:
        """Score suitable for Redis sorted sets where higher means sooner."""
        return self.score

    def to_metadata(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 6),
            "priority": round(self.priority, 6),
            "exploitability": round(self.exploitability, 6),
            "business_criticality": round(self.business_criticality, 6),
            "analyst_sla_urgency": round(self.analyst_sla_urgency, 6),
            "historical_velocity": round(self.historical_velocity, 6),
            "resource_contention": round(self.resource_contention, 6),
            "bloom_mesh_saturation": round(self.bloom_mesh_saturation, 6),
            "age_seconds": round(self.age_seconds, 3),
            "retry_penalty": round(self.retry_penalty, 6),
            "resource_types": list(self.resource_types),
            "components": {k: round(v, 6) for k, v in self.components.items()},
        }


class HasResourceHealth(Protocol):
    async def saturation_snapshot(self) -> dict[str, float]: ...


def bid_from_mapping(
    *,
    payload: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    priority: int | float = 5,
    created_at: float | None = None,
    retries: int = 0,
    resource_types: list[str] | tuple[str, ...] | None = None,
    weights: BidWeights | None = None,
    now: float | None = None,
) -> MultiObjectiveBid:
    """Build a bid from queue/task metadata."""
    payload = payload if isinstance(payload, dict) else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    weights = weights or BidWeights()
    now = time.time() if now is None else now
    created_at = _as_float(created_at, now)
    sources = _nested_sources(payload, metadata)

    priority_norm = _scale_10(priority, 5.0)
    raw_exploit = _first_present(
        *sources,
        keys=("exploitability", "exploitability_score", "epss", "cvss", "risk_score"),
        default=None,
    )
    exploitability = (
        _scale_10(raw_exploit, priority_norm) if raw_exploit is not None else _clamp(priority_norm)
    )

    raw_crit = _first_present(
        *sources,
        keys=("business_criticality", "asset_criticality", "criticality", "business_impact"),
        default=None,
    )
    business_criticality = (
        _scale_10(raw_crit, priority_norm) if raw_crit is not None else _clamp(priority_norm)
    )

    deadline = _as_float(
        _first_present(
            *sources,
            keys=("analyst_sla_deadline", "sla_deadline", "deadline_at", "due_at"),
            default=0.0,
        )
    )
    sla_seconds = _as_float(
        _first_present(*sources, keys=("analyst_sla_seconds", "sla_seconds"), default=0.0)
    )
    if deadline > 0:
        seconds_left = deadline - now
        analyst_sla = 1.0 if seconds_left <= 0 else _clamp(1.0 - (seconds_left / 86400.0))
    elif sla_seconds > 0:
        elapsed = max(0.0, now - created_at)
        analyst_sla = _clamp(elapsed / sla_seconds)
    else:
        analyst_sla = 0.25 if priority_norm >= 0.8 else 0.0

    historical_velocity = _scale_10(
        _first_present(
            *sources,
            keys=(
                "historical_scan_velocity",
                "velocity_score",
                "finding_velocity",
                "target_velocity",
            ),
            default=0.5,
        ),
        0.5,
    )
    bloom_mesh_saturation = _scale_10(
        _first_present(
            *sources,
            keys=("bloom_mesh_saturation", "mesh_saturation", "bloom_saturation"),
            default=0.0,
        ),
        0.0,
    )
    resource_contention = _scale_10(
        _first_present(
            *sources,
            keys=("resource_contention", "contention", "resource_saturation"),
            default=0.0,
        ),
        0.0,
    )

    age_seconds = max(0.0, now - created_at)
    age = _clamp(math.log1p(age_seconds) / math.log1p(3600.0))
    retry_penalty = _clamp(_as_float(retries, 0.0) / 5.0)

    components = {
        "priority": weights.priority * priority_norm,
        "exploitability": weights.exploitability * exploitability,
        "business_criticality": weights.business_criticality * business_criticality,
        "analyst_sla": weights.analyst_sla * analyst_sla,
        "historical_velocity": weights.historical_velocity * historical_velocity,
        "age": weights.age * age,
        "resource_contention": -(weights.resource_contention * resource_contention),
        "bloom_mesh_saturation": -(weights.bloom_mesh_saturation * bloom_mesh_saturation),
        "retries": -(weights.retries * retry_penalty),
    }
    score = sum(components.values())

    return MultiObjectiveBid(
        score=score,
        priority=priority_norm,
        exploitability=exploitability,
        business_criticality=business_criticality,
        analyst_sla_urgency=analyst_sla,
        historical_velocity=historical_velocity,
        resource_contention=resource_contention,
        bloom_mesh_saturation=bloom_mesh_saturation,
        age_seconds=age_seconds,
        retry_penalty=retry_penalty,
        resource_types=tuple(resource_types or ("default",)),
        components=components,
    )


def bid_for_job(
    job: Any, *, weights: BidWeights | None = None, now: float | None = None
) -> MultiObjectiveBid:
    payload = getattr(job, "payload", {}) or {}
    metadata = getattr(job, "metadata", {}) or {}
    if not isinstance(payload, dict):
        payload = {}
    if not isinstance(metadata, dict):
        metadata = {}
    return bid_from_mapping(
        payload=payload,
        metadata=metadata,
        priority=getattr(job, "priority", 5),
        created_at=getattr(job, "created_at", None),
        retries=getattr(job, "retries", 0),
        resource_types=metadata.get("resource_types"),
        weights=weights,
        now=now,
    )


def bid_for_task(
    task: Any, *, weights: BidWeights | None = None, now: float | None = None
) -> MultiObjectiveBid:
    priority = 10.0 - (float(getattr(getattr(task, "priority", 2), "value", 2)) * 2.0)
    return bid_from_mapping(
        payload=getattr(task, "kwargs", {}) or {},
        metadata=getattr(task, "metadata", {}) or {},
        priority=priority,
        created_at=(getattr(task, "metadata", {}) or {}).get("created_at"),
        retries=getattr(task, "retries", 0),
        resource_types=getattr(task, "resource_types", None),
        weights=weights,
        now=now,
    )


def bid_for_target(
    *,
    url: str,
    base_priority: float,
    metadata: dict[str, Any] | None = None,
    current_priority: float | None = None,
    weights: BidWeights | None = None,
    now: float | None = None,
) -> MultiObjectiveBid:
    payload = {"url": url}
    return bid_from_mapping(
        payload=payload,
        metadata=metadata or {},
        priority=current_priority if current_priority is not None else base_priority,
        created_at=(metadata or {}).get("created_at"),
        resource_types=(metadata or {}).get("resource_types"),
        weights=weights,
        now=now,
    )


def contention_from_pool_saturation(
    resource_types: list[str] | tuple[str, ...],
    saturation: dict[str, float],
) -> float:
    if not resource_types:
        return 0.0
    values = [saturation.get(resource, 0.0) for resource in set(resource_types)]
    return _clamp(sum(values) / max(len(values), 1))


def score_with_runtime_contention(
    bid: MultiObjectiveBid,
    *,
    resource_saturation: dict[str, float] | None = None,
    bloom_mesh_saturation: float | None = None,
    weights: BidWeights | None = None,
) -> float:
    weights = weights or BidWeights()
    score = bid.score
    if resource_saturation:
        score -= weights.resource_contention * contention_from_pool_saturation(
            bid.resource_types, resource_saturation
        )
    if bloom_mesh_saturation is not None:
        score -= weights.bloom_mesh_saturation * _clamp(bloom_mesh_saturation)
    return score
