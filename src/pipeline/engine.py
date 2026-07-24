from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, TypeVar
from uuid import uuid4

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ============================================================
# Core Pipeline Stages
# ============================================================

class Stage:
    """Base class for pipeline stages."""

    def __init__(self, name: str, config: dict | None = None):
        self.name = name
        self.config = config or {}
        self._dependencies: list[str] = []

    @property
    def dependencies(self) -> list[str]:
        return self._dependencies

    def depends_on(self, *stages: str) -> "Stage":
        self._dependencies = list(stages)
        return self

    async def execute(self, state: Any, context: Any) -> Any:
        """Override in subclass."""
        raise NotImplementedError

    async def validate_input(self, state: Any) -> bool:
        return True

    async def on_start(self, state: Any) -> None:
        pass

    async def on_complete(self, state: Any, artifacts: Any) -> None:
        pass

    async def on_failure(self, state: Any, error: Exception) -> None:
        pass


@dataclass
class StageArtifacts:
    """Artifacts produced by a stage."""
    subdomains: frozenset[str] = frozenset()
    live_hosts: frozenset[str] = frozenset()
    urls: frozenset[str] = frozenset()
    parameters: frozenset[str] = frozenset()
    priority_urls: list[dict] = field(default_factory=list)
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


class StageStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StageMetrics:
    duration_seconds: float = 0.0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    items_processed: int = 0
    items_output: int = 0
    error: str | None = None
    custom: dict = field(default_factory=dict)


@dataclass
class StageExecution:
    """Mutable execution state for a single stage."""
    name: str
    status: StageStatus = StageStatus.PENDING
    metrics: StageMetrics = field(default_factory=StageMetrics)
    artifacts: StageArtifacts = field(default_factory=StageArtifacts)
    input_snapshot: dict = field(default_factory=dict)
    checkpoints: dict = field(default_factory=dict)
    retry_count: int = 0

    def start(self) -> None:
        self.status = StageStatus.RUNNING
        self.metrics.started_at = datetime.now()

    def complete(self, artifacts: StageArtifacts | None = None, items_processed: int = 0, items_output: int = 0) -> None:
        self.status = StageStatus.COMPLETED
        self.metrics.finished_at = datetime.now()
        self.metrics.duration_seconds = (self.metrics.finished_at - self.metrics.started_at).total_seconds() if self.metrics.started_at else 0
        self.metrics.items_processed = items_processed
        self.metrics.items_output = items_output
        if artifacts:
            self.artifacts = artifacts

    def fail(self, error: str, retry: bool = False) -> None:
        self.status = StageStatus.FAILED
        self.metrics.finished_at = datetime.now()
        self.metrics.duration_seconds = (self.metrics.finished_at - self.metrics.started_at).total_seconds() if self.metrics.started_at else 0
        self.metrics.error = error
        if retry:
            self.retry_count += 1
            self.status = StageStatus.PENDING

    def skip(self, reason: str = "") -> None:
        self.status = StageStatus.SKIPPED
        self.metrics.finished_at = datetime.now()
        self.metrics.duration_seconds = (self.metrics.finished_at - self.metrics.started_at).total_seconds() if self.metrics.started_at else 0
        self.metrics.custom["skip_reason"] = reason


# ============================================================
# Pipeline State
# ============================================================

@dataclass
class PipelineState:
    """Aggregated pipeline execution state."""
    run_id: str
    target_name: str
    scope_entries: list[str]
    started_at: datetime = field(default_factory=datetime.now)
    stages: dict[str, StageExecution] = field(default_factory=dict)
    current_stage: str | None = None

    @property
    def completed_stages(self) -> list[str]:
        return [name for name, s in self.stages.items() if s.status == StageStatus.COMPLETED]

    @property
    def failed_stages(self) -> list[str]:
        return [name for name, s in self.stages.items() if s.status == StageStatus.FAILED]

    @property
    def all_artifacts(self) -> StageArtifacts:
        result = StageArtifacts()
        for stage in self.stages.values():
            result = result.merge(stage.artifacts)
        return result

    def get_stage(self, name: str) -> StageExecution:
        return self.stages.setdefault(name, StageExecution(name=name))

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "target_name": self.target_name,
            "scope_entries": self.scope_entries,
            "started_at": self.started_at.isoformat(),
            "current_stage": self.current_stage,
            "stages": {k: {
                "name": v.name,
                "status": v.status.value,
                "metrics": {
                    "duration_seconds": v.metrics.duration_seconds,
                    "started_at": v.metrics.started_at.isoformat() if v.metrics.started_at else None,
                    "finished_at": v.metrics.finished_at.isoformat() if v.metrics.finished_at else None,
                    "items_processed": v.metrics.items_processed,
                    "items_output": v.metrics.items_output,
                    "error": v.metrics.error,
                    "reason": v.metrics.reason,
                },
                "artifacts": v.artifacts.to_dict(),
            } for k, v in self.stages.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PipelineState":
        state = cls(
            run_id=data["run_id"],
            target_name=data["target_name"],
            scope_entries=data["scope_entries"],
            started_at=datetime.fromisoformat(data["started_at"]),
            current_stage=data.get("current_stage"),
        )
        for name, stage_data in data.get("stages", {}).items():
            stage = StageExecution(name=stage_data["name"])
            stage.status = StageStatus(stage_data["status"])
            m = stage_data["metrics"]
            stage.metrics = StageMetrics(
                duration_seconds=m.get("duration_seconds", 0),
                started_at=datetime.fromisoformat(m["started_at"]) if m.get("started_at") else None,
                finished_at=datetime.fromisoformat(m["finished_at"]) if m.get("finished_at") else None,
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


# ============================================================
# Pipeline Execution Context
# ============================================================

@dataclass
class ExecutionContext:
    """Context passed to stage execution."""

    run_id: str
    target_name: str
    config: dict
    storage: Any
    event_bus: Any
    checkpoint_manager: Any
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger(__name__))
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()


# ============================================================
# Pipeline Engine
# ============================================================

class PipelineEngine:
    """Executes pipeline stages with dependency resolution and error handling."""

    def __init__(
        self,
        stages: list["Stage"],
        config: dict,
        context: "ExecutionContext",
        max_retries: int = 2,
        retry_delay: float = 5.0,
    ):
        self.stages = {s.name: s for s in stages}
        self.config = config
        self.context = context
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._state: PipelineState | None = None

    def _resolve_order(self) -> list[str]:
        """Topological sort of stages by dependencies."""
        from collections import defaultdict, deque

        in_degree = {name: 0 for name in self.stages}
        adj = defaultdict(list)

        for stage in self.stages.values():
            for dep in stage.dependencies:
                if dep in self.stages:
                    adj[dep].append(stage.name)
                    in_degree[stage.name] += 1

        queue = deque([name for name, deg in in_degree.items() if deg == 0])
        result = []

        while queue:
            queue.sort()  # Deterministic order
            name = queue.popleft()
            result.append(name)
            for dependent in adj[name]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(result) != len(self.stages):
            raise ValueError("Circular dependency detected in stages")

        return result

    async def execute(self, state: PipelineState | None = None) -> PipelineState:
        if state is None:
            state = PipelineState(
                run_id=self.context.run_id,
                target_name=self.context.target_name,
                scope_entries=self.config.get("scope_entries", []),
            )

        self._state = state
        order = self._resolve_order()

        self.context.logger.info("Starting pipeline with %d stages: %s", len(order), order)

        for stage_name in order:
            if self.context.cancel_event.is_set():
                self.context.logger.warning("Pipeline cancelled")
                break

            stage = self.stages[stage_name]
            state.current_stage = stage_name
            execution = state.get_stage(stage_name)

            if not await stage.validate_input(state):
                execution.skip("Input validation failed")
                self.context.logger.warning("Stage %s skipped: input validation failed", stage_name)
                continue

            while True:
                self.context.logger.info("Executing stage: %s", stage_name)
                execution.start()

                try:
                    await stage.on_start(state)
                    artifacts = await stage.execute(state, self.context)
                    execution.complete(artifacts)
                    await stage.on_complete(state, artifacts)
                    self.context.logger.info("Stage %s completed in %.2fs", stage_name, execution.metrics.duration_seconds)
                    break
                except asyncio.CancelledError:
                    execution.fail("Pipeline cancelled")
                    raise
                except Exception as e:
                    if execution.retry_count < self.max_retries:
                        self.context.logger.warning("Stage %s failed (attempt %d/%d): %s. Retrying...",
                                                  stage_name, execution.retry_count + 1, self.max_retries + 1, e)
                        await asyncio.sleep(self.retry_delay * (execution.retry_count + 1))
                        execution.fail(str(e), retry=True)
                        continue
                    else:
                        execution.fail(str(e))
                        await stage.on_failure(state, e)
                        self.context.logger.error("Stage %s failed: %s", stage_name, e)
                        # Decide whether to continue or abort
                        if self.config.get("fail_fast", True):
                            raise
                        break
                finally:
                    # Save checkpoint after each stage attempt
                    await self._save_checkpoint(state)

        self.context.logger.info("Pipeline finished. Completed: %d, Failed: %d",
                               len(state.completed_stages), len(state.failed_stages))
        return state

    async def _save_checkpoint(self, state: PipelineState) -> None:
        if hasattr(self.context, "checkpoint_manager") and self.context.checkpoint_manager:
            await self.context.checkpoint_manager.save_checkpoint(state)