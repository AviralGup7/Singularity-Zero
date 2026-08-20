from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from src.core.models.stage_status import (
    StageStatus,
    resolve_skip_status,
    transition_stage_status,
)


@dataclass(frozen=True)
class StageMetrics:
    """Immutable metrics for a single stage."""

    duration_seconds: float = 0.0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    items_processed: int = 0
    items_output: int = 0
    error: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class StageArtifacts:
    """Immutable artifact references for a stage."""

    subdomains: frozenset[str] = frozenset()
    live_hosts: frozenset[str] = frozenset()
    urls: frozenset[str] = frozenset()
    parameters: frozenset[str] = frozenset()
    priority_urls: tuple[dict, ...] = ()
    findings: tuple[dict, ...] = ()
    screenshots: tuple[dict, ...] = ()
    waf_findings: tuple[dict, ...] = ()
    technology_summary: tuple[dict, ...] = ()
    attack_graph: dict | None = None
    endpoint_relationships: tuple[dict, ...] = ()
    finding_graph: tuple[dict, ...] = ()
    diff_summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "subdomains": list(self.subdomains),
            "live_hosts": list(self.live_hosts),
            "urls": list(self.urls),
            "parameters": list(self.parameters),
            "priority_urls": list(self.priority_urls),
            "findings": list(self.findings),
            "screenshots": list(self.screenshots),
            "waf_findings": list(self.waf_findings),
            "technology_summary": list(self.technology_summary),
            "attack_graph": self.attack_graph,
            "endpoint_relationships": list(self.endpoint_relationships),
            "finding_graph": list(self.finding_graph),
            "diff_summary": self.diff_summary,
        }


@dataclass
class StageExecution:
    """Mutable execution state for a single stage."""

    name: str
    status: StageStatus = StageStatus.PENDING
    metrics: StageMetrics = field(default_factory=StageMetrics)
    artifacts: StageArtifacts = field(default_factory=StageArtifacts)
    input_snapshot: dict = field(default_factory=dict)
    checkpoints: dict = field(default_factory=dict)

    def _set_status(self, target: StageStatus) -> bool:
        from src.core.models.stage_status import normalize_stage_status

        dest = normalize_stage_status(target)
        applied = transition_stage_status(self.status, dest)
        self.status = StageStatus(applied)
        return self.status == dest

    def mark_running(self) -> None:
        if not self._set_status(StageStatus.RUNNING):
            return
        self.metrics = StageMetrics(started_at=datetime.now())

    def mark_completed(self, artifacts: StageArtifacts | None = None) -> None:
        if not self._set_status(StageStatus.COMPLETED):
            return
        duration = 0.0
        if self.metrics.started_at:
            duration = (datetime.now() - self.metrics.started_at).total_seconds()
        self.metrics = StageMetrics(
            duration_seconds=duration,
            finished_at=datetime.now(),
        )
        if artifacts:
            self.artifacts = artifacts

    def mark_failed(self, error: str, reason: str = "") -> None:
        if not self._set_status(StageStatus.FAILED):
            return
        duration = 0.0
        if self.metrics.started_at:
            duration = (datetime.now() - self.metrics.started_at).total_seconds()
        self.metrics = StageMetrics(
            duration_seconds=duration,
            finished_at=datetime.now(),
            error=error,
            reason=reason,
        )

    def mark_degraded(self, error: str, reason: str = "") -> None:
        if not self._set_status(StageStatus.DEGRADED):
            return
        self.metrics = StageMetrics(
            duration_seconds=(datetime.now() - self.metrics.started_at).total_seconds()
            if self.metrics.started_at
            else 0,
            finished_at=datetime.now(),
            error=error,
            reason=reason,
        )

    def mark_skipped(self, reason: str = "") -> None:
        if not self._set_status(resolve_skip_status(reason)):
            return
        self.metrics = StageMetrics(reason=reason)


@dataclass
class PipelineState:
    """Aggregated pipeline execution state."""

    run_id: str
    target_name: str
    scope_entries: list[str]
    started_at: datetime = field(default_factory=datetime.now)
    stages: dict[str, StageExecution] = field(default_factory=dict)

    # Derived properties
    @property
    def all_subdomains(self) -> frozenset[str]:
        return frozenset().union(*[s.artifacts.subdomains for s in self.stages.values()])

    @property
    def all_live_hosts(self) -> frozenset[str]:
        return frozenset().union(*[s.artifacts.live_hosts for s in self.stages.values()])

    @property
    def all_urls(self) -> frozenset[str]:
        return frozenset().union(*[s.artifacts.urls for s in self.stages.values()])

    @property
    def all_parameters(self) -> frozenset[str]:
        return frozenset().union(*[s.artifacts.parameters for s in self.stages.values()])

    @property
    def all_findings(self) -> list[dict]:
        findings = []
        for stage in self.stages.values():
            findings.extend(stage.artifacts.findings)
        return findings

    @property
    def completed_stages(self) -> list[str]:
        return [name for name, s in self.stages.items() if s.status == StageStatus.COMPLETED]

    @property
    def failed_stages(self) -> list[str]:
        return [name for name, s in self.stages.items() if s.status == StageStatus.FAILED]

    def get_stage(self, name: str) -> StageExecution:
        return self.stages.setdefault(name, StageExecution(name=name))

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "target_name": self.target_name,
            "scope_entries": self.scope_entries,
            "started_at": self.started_at.isoformat(),
            "stages": {
                k: {
                    "name": v.name,
                    "status": v.status.value,
                    "metrics": {
                        "duration_seconds": v.metrics.duration_seconds,
                        "started_at": v.metrics.started_at.isoformat()
                        if v.metrics.started_at
                        else None,
                        "finished_at": v.metrics.finished_at.isoformat()
                        if v.metrics.finished_at
                        else None,
                        "items_processed": v.metrics.items_processed,
                        "items_output": v.metrics.items_output,
                        "error": v.metrics.error,
                        "reason": v.metrics.reason,
                    },
                    "artifacts": v.artifacts.to_dict(),
                }
                for k, v in self.stages.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> PipelineState:
        state = cls(
            run_id=data["run_id"],
            target_name=data["target_name"],
            scope_entries=data["scope_entries"],
            started_at=datetime.fromisoformat(data["started_at"]),
        )
        for name, stage_data in data.get("stages", {}).items():
            stage = StageExecution(name=name)
            stage.status = StageStatus(stage_data["status"])

            m = stage_data["metrics"]
            stage.metrics = StageMetrics(
                duration_seconds=m.get("duration_seconds", 0),
                started_at=datetime.fromisoformat(m["started_at"]) if m.get("started_at") else None,
                finished_at=datetime.fromisoformat(m["finished_at"])
                if m.get("finished_at")
                else None,
                items_processed=m.get("items_processed", 0),
                items_output=m.get("items_output", 0),
                error=m.get("error"),
                reason=m.get("reason", ""),
            )
            a = stage_data.get("artifacts", {})
            stage.artifacts = StageArtifacts(
                subdomains=frozenset(a.get("subdomains", [])),
                live_hosts=frozenset(a.get("live_hosts", [])),
                urls=frozenset(a.get("urls", [])),
                parameters=frozenset(a.get("parameters", [])),
                priority_urls=tuple(a.get("priority_urls", [])),
                findings=tuple(a.get("findings", [])),
                screenshots=tuple(a.get("screenshots", [])),
                waf_findings=tuple(a.get("waf_findings", [])),
                technology_summary=tuple(a.get("technology_summary", [])),
                attack_graph=a.get("attack_graph"),
                endpoint_relationships=tuple(a.get("endpoint_relationships", [])),
                finding_graph=tuple(a.get("finding_graph", [])),
                diff_summary=a.get("diff_summary", {}),
            )
            state.stages[name] = stage
        return state
