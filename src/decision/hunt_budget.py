"""HuntBudget configuration for time-, effort-, and discovery-bounded hunts.

A :class:`HuntBudget` is a structured upper bound on the resources a
hunt may consume before the orchestrator should pivot to the next
priority target. It is consumed by:

* :class:`src.decision.priority_queue.CorrelationPriorityQueue` — to
  short-circuit ``should_terminate_early`` when the time/request/finding
  budget is exhausted.
* :class:`src.pipeline.hunt_mode.HuntModeController` — to flip into a
  low-friction "time-boxed" sub-mode.
* ``run_orchestrator`` — to expose the budget in the run summary so
  reviewers know whether a run was truncated.

Three orthogonal budget axes are modelled:

* **Time** — wall-clock seconds the hunt may consume.
* **Requests** — total HTTP requests emitted (any direction).
* **Findings** — *productive* findings (confidence above threshold) the
  hunt is expected to surface; once we exceed this many productive
  findings the queue can stop early without losing value.

In addition, the **hunter-centric** budget adds:

* ``stop_when_high_confidence_count`` — exit early when N productive
  findings reach the high-confidence threshold (typically 0.95+).
* ``high_value_target_time_budget_pct`` — fraction of total time the
  scheduler should reserve for high-value targets.
* ``max_concurrent_probes`` — cap on parallel probe count; used by the
  fast-path dispatcher.
* ``countdown_visible`` — whether the UI should display the remaining
  budget as a live countdown.

Each axis is *optional*; setting it to ``None`` removes the cap. The
:class:`HuntBudgetEnforcer` evaluates the three axes on each poll and
exposes :py:meth:`HuntBudgetEnforcer.is_exhausted` / :py:meth:`exhausted_axes`
for the orchestrator.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


# Default category weights for "high-value" bug-bounty categories.
# Operators can override the list via ``hunt_mode.high_value_categories``.
DEFAULT_HIGH_VALUE_CATEGORIES: tuple[str, ...] = (
    "idor",
    "bola",
    "ssrf",
    "ssti",
    "rce",
    "command_injection",
    "auth_bypass",
    "access_control",
    "open_redirect",
    "file_upload",
    "insecure_deserialization",
    "xss",
    "broken_authentication",
    "mass_assignment",
    "excessive_data_exposure",
)


_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class BudgetAxis(StrEnum):
    """Names of the three orthogonal budget axes."""

    TIME = "time"
    REQUESTS = "requests"
    FINDINGS = "findings"


@dataclass
class HuntMode:
    """Operational toggle for the bug-bounty hunting preset.

    Unlike :class:`HuntBudget` (which is the per-run *resource* cap),
    :class:`HuntMode` is the *behaviour* switch: which categories are
    considered high-value, which findings count as low-hanging-fruit,
    and whether subdomain enumeration / passive checks should be
    skipped to maximise payout per hour.
    """

    enabled: bool = False
    skip_subdomain_enumeration: bool = True
    skip_passive_checks: bool = False
    high_value_categories: tuple[str, ...] = DEFAULT_HIGH_VALUE_CATEGORIES
    low_hanging_fruit_path_keywords: tuple[str, ...] = (
        "admin",
        "auth",
        "login",
        "oauth",
        "api",
        "user",
        "account",
        "internal",
        "debug",
    )
    low_hanging_fruit_min_severity: str = "medium"
    low_hanging_fruit_min_confidence: float = 0.7
    low_hanging_fruit_max_findings: int = 50
    deduplicate_against_history: bool = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None) -> HuntMode:
        section = (config or {}).get("hunt_mode") or {}
        if not isinstance(section, Mapping):
            return cls()
        lhf = section.get("low_hanging_fruit") or {}
        categories = tuple(
            str(c).lower()
            for c in section.get(
                "high_value_categories", DEFAULT_HIGH_VALUE_CATEGORIES
            )
            if c
        ) or DEFAULT_HIGH_VALUE_CATEGORIES
        return cls(
            enabled=bool(section.get("enabled", False)),
            skip_subdomain_enumeration=bool(
                section.get("skip_subdomain_enumeration", True)
            ),
            skip_passive_checks=bool(section.get("skip_passive_checks", False)),
            high_value_categories=categories,
            low_hanging_fruit_path_keywords=tuple(
                str(k).lower()
                for k in lhf.get(
                    "path_keywords", cls().low_hanging_fruit_path_keywords
                )
            ),
            low_hanging_fruit_min_severity=str(
                lhf.get("min_severity", "medium")
            ).lower(),
            low_hanging_fruit_min_confidence=float(
                lhf.get("min_confidence", 0.7)
            ),
            low_hanging_fruit_max_findings=int(lhf.get("max_findings", 50)),
            deduplicate_against_history=bool(
                section.get("deduplicate_against_history", True)
            ),
        )

    def is_high_value(self, category: str) -> bool:
        cat = str(category or "").lower()
        return any(hv in cat for hv in self.high_value_categories)

    def is_low_hanging_fruit(
        self,
        *,
        category: str,
        severity: str,
        confidence: float,
        url: str,
    ) -> bool:
        """Return True if a finding qualifies as low-hanging-fruit."""
        sev = str(severity or "").lower()
        min_sev = _SEVERITY_RANK.get(self.low_hanging_fruit_min_severity, 2)
        rank = _SEVERITY_RANK.get(sev, -1)
        if rank < min_sev:
            return False
        if float(confidence or 0.0) < self.low_hanging_fruit_min_confidence:
            return False
        url_lower = str(url or "").lower()
        return any(kw in url_lower for kw in self.low_hanging_fruit_path_keywords)


@dataclass
class HuntBudget:
    """Declarative budget for a single hunt run.

    All fields are optional. A field of ``None`` means "unbounded on
    that axis".  A field of ``0`` means "do not even start". The
    default values give an effectively unbounded budget, which keeps
    backwards compatibility with callers that do not specify one.

    Hunter-centric extensions:

    * ``stop_when_high_confidence_count`` — exit early once the
      enforcer has recorded that many *high-confidence* findings
      (default confidence ≥ 0.95).
    * ``high_value_target_time_budget_pct`` — fraction of
      ``max_duration_seconds`` reserved for high-value targets.
      ``0.4`` means 40 %.
    * ``max_concurrent_probes`` — cap on concurrent probe count;
      consumed by the fast-path dispatcher.
    * ``countdown_visible`` — UI hint; consumed by the evasion page.
    """

    max_duration_seconds: float | None = None
    max_requests: int | None = None
    max_findings: int | None = None
    confidence_threshold: float = 0.7
    label: str = "default"
    # Hunter-centric extensions.
    stop_when_high_confidence_count: int | None = None
    high_value_target_time_budget_pct: float = 0.4
    high_confidence_threshold: float = 0.95
    max_concurrent_probes: int = 5
    countdown_visible: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_duration_seconds": self.max_duration_seconds,
            "max_requests": self.max_requests,
            "max_findings": self.max_findings,
            "confidence_threshold": self.confidence_threshold,
            "label": self.label,
            "stop_when_high_confidence_count": self.stop_when_high_confidence_count,
            "high_value_target_time_budget_pct": self.high_value_target_time_budget_pct,
            "high_confidence_threshold": self.high_confidence_threshold,
            "max_concurrent_probes": self.max_concurrent_probes,
            "countdown_visible": self.countdown_visible,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> HuntBudget:
        if not isinstance(payload, Mapping):
            return cls()
        return cls(
            max_duration_seconds=_coerce_optional_float(
                payload.get("max_duration_seconds")
                or payload.get("max_wall_clock_seconds")
            ),
            max_requests=_coerce_optional_int(
                payload.get("max_requests") or payload.get("max_http_requests")
            ),
            max_findings=_coerce_optional_int(
                payload.get("max_findings")
                or payload.get("max_productive_findings")
                or payload.get("stop_when_total_findings")
            ),
            confidence_threshold=_coerce_optional_float(
                payload.get("confidence_threshold")
            ) or 0.7,
            label=str(payload.get("label") or "default"),
            stop_when_high_confidence_count=_coerce_optional_int(
                payload.get("stop_when_high_confidence_count")
            ),
            high_value_target_time_budget_pct=_coerce_optional_float(
                payload.get("high_value_target_time_budget_pct")
            )
            or 0.4,
            high_confidence_threshold=_coerce_optional_float(
                payload.get("high_confidence_threshold")
            )
            or 0.95,
            max_concurrent_probes=_coerce_optional_int(
                payload.get("max_concurrent_probes")
            )
            or 5,
            countdown_visible=bool(payload.get("countdown_visible", True)),
        )

    def is_bounded(self) -> bool:
        return any(
            axis is not None
            for axis in (
                self.max_duration_seconds,
                self.max_requests,
                self.max_findings,
            )
        )


@dataclass
class BudgetSnapshot:
    """A single point-in-time snapshot of the enforcer's counters."""

    elapsed_seconds: float
    requests_emitted: int
    productive_findings: int
    exhausted_axes: list[BudgetAxis] = field(default_factory=list)
    terminated_early: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "requests_emitted": self.requests_emitted,
            "productive_findings": self.productive_findings,
            "exhausted_axes": [axis.value for axis in self.exhausted_axes],
            "terminated_early": self.terminated_early,
        }


class HuntBudgetEnforcer:
    """Stateful enforcer that tracks the three budget axes.

    The orchestrator calls :py:meth:`record_request` after each
    outbound request, :py:meth:`record_finding` whenever a productive
    finding (confidence >= ``confidence_threshold``) is emitted, and
    :py:meth:`snapshot` (or :py:meth:`is_exhausted`) on each scheduling
    tick.

    The enforcer is *fail-open* — if the budget is unbounded on an
    axis, that axis never reports as exhausted.
    """

    def __init__(self, budget: HuntBudget | None = None) -> None:
        self._budget = budget or HuntBudget()
        self._start = time.monotonic()
        self._requests_emitted = 0
        self._productive_findings = 0
        self._high_confidence_findings = 0
        self._terminated_early = False
        self._last_snapshot = BudgetSnapshot(
            elapsed_seconds=0.0,
            requests_emitted=0,
            productive_findings=0,
        )

    @property
    def budget(self) -> HuntBudget:
        return self._budget

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start

    @property
    def requests_emitted(self) -> int:
        return self._requests_emitted

    @property
    def productive_findings(self) -> int:
        return self._productive_findings

    @property
    def high_confidence_findings(self) -> int:
        return self._high_confidence_findings

    @property
    def terminated_early(self) -> bool:
        return self._terminated_early

    @classmethod
    def from_config(
        cls, config: Mapping[str, Any] | None, *, label: str = "default"
    ) -> HuntBudgetEnforcer:
        """Build an enforcer from the ``hunt_budget`` block of the config."""
        section: Mapping[str, Any] | None = None
        if isinstance(config, Mapping):
            section = config.get("hunt_budget")
        budget = HuntBudget.from_mapping(section)
        if budget.label == "default" and label != "default":
            budget = HuntBudget(
                **{
                    **budget.to_dict(),
                    "label": label,
                }
            )
        return cls(budget=budget)

    def record_request(self, count: int = 1) -> None:
        if count <= 0:
            return
        self._requests_emitted += int(count)

    def record_finding(self, confidence: float) -> None:
        if confidence < self._budget.confidence_threshold:
            return
        self._productive_findings += 1
        if confidence >= self._budget.high_confidence_threshold:
            self._high_confidence_findings += 1

    def reset(self) -> None:
        self._start = time.monotonic()
        self._requests_emitted = 0
        self._productive_findings = 0
        self._high_confidence_findings = 0
        self._terminated_early = False
        self._last_snapshot = BudgetSnapshot(
            elapsed_seconds=0.0,
            requests_emitted=0,
            productive_findings=0,
        )

    def exhausted_axes(self) -> list[BudgetAxis]:
        axes: list[BudgetAxis] = []
        if (
            self._budget.max_duration_seconds is not None
            and self.elapsed_seconds >= self._budget.max_duration_seconds
        ):
            axes.append(BudgetAxis.TIME)
        if (
            self._budget.max_requests is not None
            and self._requests_emitted >= self._budget.max_requests
        ):
            axes.append(BudgetAxis.REQUESTS)
        if (
            self._budget.max_findings is not None
            and self._productive_findings >= self._budget.max_findings
        ):
            axes.append(BudgetAxis.FINDINGS)
        if (
            self._budget.stop_when_high_confidence_count is not None
            and self._high_confidence_findings
            >= self._budget.stop_when_high_confidence_count
        ):
            # High-confidence short-circuit is folded into the FINDINGS
            # axis because the orchestrator polls for "exhausted axes",
            # not for individual reasons.
            if BudgetAxis.FINDINGS not in axes:
                axes.append(BudgetAxis.FINDINGS)
        return axes

    def is_exhausted(self) -> bool:
        return bool(self.exhausted_axes())

    def mark_terminated(self, reason: str | None = None) -> None:
        if not self._terminated_early:
            self._terminated_early = True
            logger.info(
                "[HuntBudget] early-termination requested label=%s reason=%s axes=%s",
                self._budget.label,
                reason or "unspecified",
                [axis.value for axis in self.exhausted_axes()],
            )

    def snapshot(self) -> BudgetSnapshot:
        axes = self.exhausted_axes()
        snap = BudgetSnapshot(
            elapsed_seconds=self.elapsed_seconds,
            requests_emitted=self._requests_emitted,
            productive_findings=self._productive_findings,
            exhausted_axes=axes,
            terminated_early=self._terminated_early or bool(axes),
        )
        self._last_snapshot = snap
        return snap

    def previous_snapshot(self) -> BudgetSnapshot:
        return self._last_snapshot

    def bind_to_priority_queue(self, queue: Any) -> None:
        """Wire ``queue.should_terminate_early`` to this enforcer.

        Wraps the queue's existing ``should_terminate_early`` so it
        returns ``True`` whenever any budget axis is exhausted. The
        queue's own heuristic still runs for low-priority early-out.
        """
        original = getattr(queue, "should_terminate_early", None)
        if not callable(original):
            raise TypeError(
                "queue does not expose a callable should_terminate_early()"
            )

        enforcer = self

        def should_terminate_early(*args: Any, **kwargs: Any) -> bool:
            if enforcer.is_exhausted():
                enforcer.mark_terminated("budget_exhausted")
                return True
            return bool(original(*args, **kwargs))

        queue.should_terminate_early = should_terminate_early  # type: ignore[method-assign]


def _coerce_optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if result < 0:
        return None
    return result


def _coerce_optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    if result < 0:
        return None
    return result


__all__ = [
    "BudgetAxis",
    "BudgetSnapshot",
    "DEFAULT_HIGH_VALUE_CATEGORIES",
    "HuntBudget",
    "HuntBudgetEnforcer",
    "HuntMode",
]
