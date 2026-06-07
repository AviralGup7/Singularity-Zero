from __future__ import annotations

import copy
import reprlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

RUNTIME_CONTRACT_VERSION = "v1"


def _freeze_value(value: Any) -> Any:
    """Recursively freeze a value to ensure immutability and mesh-portability."""
    # --- Frontier Fix: Handle accelerated types ---
    try:
        import numpy as np

        if isinstance(value, np.ndarray):
            return tuple(_freeze_value(x) for x in value.tolist())
        if isinstance(value, (np.integer, np.floating)):
            return value.item()
    except ImportError:
        pass

    if isinstance(value, MappingProxyType):
        return value
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze_value(v) for k, v in value.items()})
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze_value(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(item) for item in value)

    try:
        return copy.deepcopy(value)
    except Exception:  # noqa: S110
        if hasattr(value, "__dict__"):
            try:
                return MappingProxyType(
                    {key: _freeze_value(item) for key, item in vars(value).items()}
                )
            except Exception:  # noqa: S110
                pass
        return reprlib.repr(value)


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw_value(v) for k, v in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_thaw_value(item) for item in value]
    return value


class ThawingMapping(Mapping):
    """A read-only Mapping wrapper that lazily thaws returned values."""

    def __init__(self, underlying: Mapping[Any, Any]):
        self._underlying = underlying

    def __getitem__(self, key: Any) -> Any:
        return _thaw_value(self._underlying[key])

    def __iter__(self) -> Iterator[Any]:
        return iter(self._underlying)

    def __len__(self) -> int:
        return len(self._underlying)

    def __repr__(self) -> str:
        return f"ThawingMapping({self._underlying!r})"


class StageOutcome(StrEnum):
    """Stable stage outcomes for contract/event payloads."""

    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class PipelineInput:
    """Immutable pipeline bootstrap contract."""

    target_name: str
    scope_entries: tuple[str, ...]
    run_id: str
    contract_version: str = RUNTIME_CONTRACT_VERSION
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)
    auth: Mapping[str, Any] | None = None
    scan_session: Any | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope_entries", tuple(self.scope_entries))
        object.__setattr__(self, "metadata", _freeze_value(dict(self.metadata or {})))
        object.__setattr__(self, "auth", _freeze_value(dict(self.auth or {})))

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "target_name": self.target_name,
            "scope_entries": list(self.scope_entries),
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "metadata": _thaw_value(self.metadata),
            "auth": _thaw_value(self.auth),
            "scan_session": None if self.scan_session is None else str(self.scan_session.scan_id),
        }


@dataclass(frozen=True, slots=True)
class StageInput:
    """Immutable snapshot consumed by an individual stage."""

    stage_name: str
    stage_index: int
    stage_total: int
    pipeline: PipelineInput
    state_snapshot: Mapping[str, Any]
    runtime: Mapping[str, Any] = field(default_factory=dict)
    previous_deltas: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    contract_version: str = RUNTIME_CONTRACT_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "state_snapshot", ThawingMapping(_freeze_value(dict(self.state_snapshot or {})))
        )
        object.__setattr__(self, "runtime", ThawingMapping(_freeze_value(dict(self.runtime or {}))))
        object.__setattr__(
            self,
            "previous_deltas",
            tuple(ThawingMapping(_freeze_value(d)) for d in (self.previous_deltas or ())),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "stage_name": self.stage_name,
            "stage_index": self.stage_index,
            "stage_total": self.stage_total,
            "pipeline": self.pipeline.to_dict(),
            "state_snapshot": _thaw_value(self.state_snapshot),
            "runtime": _thaw_value(self.runtime),
            "previous_deltas": [_thaw_value(d) for d in self.previous_deltas],
        }


@dataclass(frozen=True, slots=True)
class StageInputView:
    """Immutable, copy-on-write snapshot of pipeline state for a single stage.

    A stage receives a ``StageInputView`` rather than a mutable
    ``PipelineContext``.  Writes must be captured in a ``StageOutput``
    delta; the orchestrator merges explicitly.  This prevents accidental
    in-place mutation corrupting downstream stages.
    """

    stage_name: str
    state_snapshot: Mapping[str, Any]
    scope_entries: tuple[str, ...]
    previous_deltas: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    contract_version: str = RUNTIME_CONTRACT_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "state_snapshot",
            ThawingMapping(_freeze_value(dict(self.state_snapshot or {}))),
        )
        object.__setattr__(
            self,
            "previous_deltas",
            tuple(ThawingMapping(_freeze_value(d)) for d in (self.previous_deltas or ())),
        )

    def get(self, key: str, default: Any = None) -> Any:
        return self.state_snapshot.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self.state_snapshot


@dataclass(frozen=True, slots=True)
class StageOutput:
    """Immutable stage completion contract produced by orchestrator state merge."""

    stage_name: str
    outcome: StageOutcome
    duration_seconds: float
    retry_count: int = 0
    reason: str = ""
    error: str = ""
    metrics: Mapping[str, Any] = field(default_factory=dict)
    artifacts: Mapping[str, Any] = field(default_factory=dict)
    state_delta: Mapping[str, Any] = field(default_factory=dict)
    findings: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    contract_version: str = RUNTIME_CONTRACT_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "duration_seconds", float(max(0.0, self.duration_seconds)))
        object.__setattr__(self, "retry_count", int(max(0, self.retry_count)))
        object.__setattr__(self, "metrics", _freeze_value(dict(self.metrics or {})))
        object.__setattr__(self, "artifacts", _freeze_value(dict(self.artifacts or {})))
        object.__setattr__(self, "state_delta", _freeze_value(dict(self.state_delta or {})))
        object.__setattr__(self, "findings", tuple(_freeze_value(dict(f or {})) for f in (self.findings or ())))

    @classmethod
    def from_stage_state(
        cls,
        stage_name: str,
        state: str,
        duration_seconds: float,
        metrics: Mapping[str, Any] | None = None,
        artifacts: Mapping[str, Any] | None = None,
        state_delta: Mapping[str, Any] | None = None,
    ) -> StageOutput:
        normalized = str(state or "").upper()
        if normalized == "FAILED":
            outcome = StageOutcome.FAILED
        elif normalized == "SKIPPED":
            outcome = StageOutcome.SKIPPED
        else:
            outcome = StageOutcome.COMPLETED
        metric_data = dict(metrics or {})
        findings_list = (state_delta or {}).get("reportable_findings", []) or []
        return cls(
            stage_name=stage_name,
            outcome=outcome,
            duration_seconds=duration_seconds,
            retry_count=int(metric_data.get("retry_count", 0) or 0),
            reason=str(metric_data.get("reason", "") or ""),
            error=str(metric_data.get("error", "") or ""),
            metrics=metric_data,
            artifacts=dict(artifacts or {}),
            state_delta=dict(state_delta or {}),
            findings=tuple(findings_list),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "stage_name": self.stage_name,
            "outcome": self.outcome.value,
            "duration_seconds": self.duration_seconds,
            "retry_count": self.retry_count,
            "reason": self.reason,
            "error": self.error,
            "metrics": _thaw_value(self.metrics),
            "artifacts": _thaw_value(self.artifacts),
            "state_delta": _thaw_value(self.state_delta),
        }
