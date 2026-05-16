from __future__ import annotations

import json
import logging
import time
from dataclasses import MISSING, dataclass, field
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, TypedDict

from src.core.frontier.state import NeuralState


class StageName(StrEnum):
    """Valid pipeline stage identifiers."""

    SCOPE = "scope"
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    HOST_PROBING = "host_probing"
    SERVICE_ENUMERATION = "service_enumeration"
    URL_COLLECTION = "url_collection"
    PARAMETER_DISCOVERY = "parameter_discovery"
    TARGET_PROFILING = "target_profiling"
    DEEP_ANALYSIS = "deep_analysis"
    VALIDATION = "validation"
    MERGING = "merging"
    REPORTING = "reporting"
    SCREENSHOTS = "screenshots"
    DIFF = "diff"
    NUCLEI_SCAN = "nuclei_scan"


class StageStatus(StrEnum):
    """Lifecycle status of a pipeline stage."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class StageMetric(TypedDict, total=False):
    """Per-stage metrics recorded during execution."""

    duration_seconds: float
    started_at: float
    finished_at: float
    status: str
    error: str
    items_processed: int
    items_output: int
    reason: str



logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    """Consolidated result of all pipeline stages with CRDT synchronization."""

    # ------------------------------------------------------------------
    # Neural-Mesh Resilience Core
    # ------------------------------------------------------------------

    #: Internal CRDT state container for synchronization across stage deltas.
    _neural_state: NeuralState = field(default_factory=NeuralState, repr=False)

    # ------------------------------------------------------------------
    # Configuration / bootstrap
    # ------------------------------------------------------------------

    scope_entries: list[str] = field(default_factory=list)
    use_cache: bool = False
    module_metrics: dict[str, Any] = field(default_factory=dict)
    previous_run: Path | None = None
    tool_status: dict[str, Any] = field(default_factory=dict)
    flow_manifest: dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    discovery_enabled: bool = True
    stage_status: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Pipeline State
    # ------------------------------------------------------------------

    subdomains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    reportable_findings: list[dict[str, Any]] = field(default_factory=list)

    live_records: list[dict[str, Any]] = field(default_factory=list)
    live_hosts: set[str] = field(default_factory=set)
    service_results: dict[str, Any] = field(default_factory=dict)
    url_stage_meta: dict[str, Any] = field(default_factory=dict)
    parameters: set[str] = field(default_factory=set)
    target_profile: dict[str, Any] = field(default_factory=dict)
    history_feedback: dict[str, Any] = field(default_factory=dict)
    ranked_priority_urls: list[dict[str, Any]] = field(default_factory=list)
    priority_urls: list[str] = field(default_factory=list)
    selected_priority_items: list[dict[str, Any]] = field(default_factory=list)
    selection_meta: dict[str, Any] = field(default_factory=dict)
    deep_analysis_urls: list[str] = field(default_factory=list)
    analysis_results: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    validation_runtime_inputs: dict[str, Any] = field(default_factory=dict)
    validation_summary: dict[str, Any] = field(default_factory=dict)
    campaign_summary: dict[str, Any] = field(default_factory=dict)
    merged_findings: list[dict[str, Any]] = field(default_factory=list)
    iterative_stop_reason: str = ""
    executed_iterations: int = 0
    passive_scan_ok: bool = False
    validation_ok: bool = False
    remediation_logic: dict[str, Any] = field(default_factory=dict)

    def apply_state_delta(self, delta: dict[str, Any]) -> None:
        """Atomically merge an incremental delta using Neural-Mesh logic."""
        # 1. Update CRDT sets
        self._neural_state.apply_delta(delta)

        # 2. Update auxiliary fields (Legacy/Non-resilient)
        for key, value in delta.items():
            if key == "findings":
                key = "reportable_findings"

            if hasattr(self, key):
                current = getattr(self, key)
                if isinstance(current, dict) and isinstance(value, dict):
                    current.update(value)
                elif isinstance(current, set) and isinstance(value, (list, tuple, set, frozenset)):
                    current.update(value)
                elif isinstance(current, list) and isinstance(value, list):
                    setattr(self, key, value)  # Replacement rule as per architecture.md
                elif isinstance(current, list) and isinstance(value, (tuple, set, frozenset)):
                    setattr(self, key, list(value))
                else:
                    setattr(self, key, value)

    #: Screenshot results (each entry contains URL, path, dimensions, etc.)
    screenshots: list[dict[str, Any]] = field(default_factory=list)

    #: Artifact diff summary comparing current vs previous run results
    diff_summary: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Nuclei scan results
    # ------------------------------------------------------------------

    #: Parsed findings from Nuclei JSONL output
    nuclei_findings: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of all fields.

        Sets are converted to sorted lists. ``Path`` objects are
        converted to their string representation.
        """
        data: dict[str, Any] = {}
        for f in self.__dataclass_fields__.values():
            value = getattr(self, f.name)
            data[f.name] = self._serialize_value(value)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StageResult:
        """Create a ``StageResult`` from a dictionary.

        Lists that correspond to set fields are converted back to sets.
        String paths are converted back to ``Path`` objects.
        """
        set_fields = {
            "subdomains",
            "live_hosts",
            "urls",
            "parameters",
        }
        kwargs: dict[str, Any] = {}
        for f in cls.__dataclass_fields__.values():
            if f.name == "_neural_state":
                kwargs[f.name] = cls._restore_neural_state(data.get(f.name), data)
                continue

            value = data.get(f.name)
            if value is None:
                if f.default is not MISSING:
                    value = f.default
                elif f.default_factory is not MISSING:
                    value = f.default_factory()
                else:
                    continue

            if f.name in set_fields and isinstance(value, list):
                value = set(value)
            elif f.name == "previous_run" and isinstance(value, str):
                value = Path(value)

            kwargs[f.name] = value
        return cls(**kwargs)

    @staticmethod
    def _serialize_value(value: Any) -> Any:
        if isinstance(value, NeuralState):
            return value.get_snapshot()
        if isinstance(value, set):
            return sorted(value)
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {k: StageResult._serialize_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [StageResult._serialize_value(v) for v in value]
        return value

    @staticmethod
    def _restore_neural_state(value: Any, data: dict[str, Any]) -> NeuralState:
        state = NeuralState()
        snapshot = value if isinstance(value, dict) else data
        state.apply_delta(
            {
                "subdomains": list(snapshot.get("subdomains", []) or []),
                "urls": list(snapshot.get("urls", []) or []),
                "findings": list(
                    snapshot.get("findings")
                    or snapshot.get("reportable_findings")
                    or []
                ),
            }
        )
        return state

    def to_json(self) -> str:
        """Serialize the instance to a JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_json(cls, data: str) -> StageResult:
        """Deserialize a ``StageResult`` from a JSON string."""
        return cls.from_dict(json.loads(data))

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable snapshot of all fields.

        Alias for :meth:`to_dict` provided for semantic clarity when
        the caller intends to persist or transmit the state.
        """
        return self.to_dict()

    @classmethod
    def restore(cls, snapshot: dict[str, Any]) -> StageResult:
        """Reconstruct a ``StageResult`` from a snapshot dictionary.

        Alias for :meth:`from_dict` provided for semantic clarity when
        the caller is restoring previously persisted state.
        """
        return cls.from_dict(snapshot)


@dataclass
class PipelineContext:
    """Typed wrapper around :class:`StageResult` with an output store reference.

    Provides convenience methods for stage lifecycle management
    (marking stages complete, failed, or skipped) while keeping the
    underlying ``StageResult`` fields directly accessible.

    The ``output_store`` field holds a reference to a ``PipelineOutputStore``
    instance.  It is typed as ``Any`` to avoid a circular import — the
    actual type is defined in the pipeline output module.
    """

    result: StageResult = field(default_factory=StageResult)
    output_store: Any = None
    _checkpoint_mgr: Any = field(default=None, repr=False)

    def save_checkpoint_delta(self, stage_name: str, delta: dict[str, Any], metadata: dict[str, Any] | None = None) -> None:
        """Persist an incremental stage delta to the checkpoint manager for mid-stage resume."""
        if self._checkpoint_mgr:
            try:
                self._checkpoint_mgr.save_stage_delta(stage_name, delta, metadata=metadata)
                logger.debug("Persisted mid-stage delta for '%s': %s", stage_name, list(delta.keys()))
            except Exception as exc:
                logger.warning("Failed to save mid-stage delta for '%s': %s", stage_name, exc)

    # ------------------------------------------------------------------
    # Stage lifecycle helpers
    # ------------------------------------------------------------------

    def mark_stage_complete(self, name: str, metrics: StageMetric | None = None) -> None:
        """Mark a stage as ``COMPLETED`` and record optional metrics."""
        self.result.stage_status[name] = StageStatus.COMPLETED.value
        if metrics:
            self.result.module_metrics[name] = dict(metrics)

    def mark_stage_degraded(self, name: str, reason: str = "") -> None:
        """Mark a stage as ``DEGRADED`` (completed with non-fatal issues)."""
        self.result.stage_status[name] = StageStatus.DEGRADED.value
        meta: dict[str, Any] = self.result.module_metrics.get(name, {})
        meta["status"] = "degraded"
        meta["reason"] = reason
        meta["finished_at"] = time.time()
        self.result.module_metrics[name] = meta

    def mark_stage_failed(self, name: str, error: str = "") -> None:
        """Mark a stage as ``FAILED`` and record the error message."""
        self.result.stage_status[name] = StageStatus.FAILED.value
        meta: dict[str, Any] = self.result.module_metrics.get(name, {})
        meta["status"] = "failed"
        meta["error"] = error
        meta["finished_at"] = time.time()
        self.result.module_metrics[name] = meta

    def mark_stage_skipped(self, name: str, reason: str = "") -> None:
        """Mark a stage as ``SKIPPED`` with an optional reason."""
        self.result.stage_status[name] = StageStatus.SKIPPED.value
        meta: dict[str, Any] = self.result.module_metrics.get(name, {})
        meta["reason"] = reason
        meta["finished_at"] = time.time()
        self.result.module_metrics[name] = meta

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of the context state."""
        data = self.result.to_dict()
        data["output_store"] = None  # output_store is not serializable
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PipelineContext:
        """Create a ``PipelineContext`` from a dictionary."""
        snapshot = {k: v for k, v in data.items() if k != "output_store"}
        result = StageResult.from_dict(snapshot)
        return cls(result=result)

    def to_json(self) -> str:
        """Serialize the context to a JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_json(cls, data: str) -> PipelineContext:
        """Deserialize a ``PipelineContext`` from a JSON string."""
        return cls.from_dict(json.loads(data))

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable snapshot of the full context."""
        return self.to_dict()

    @classmethod
    def restore(cls, snapshot: dict[str, Any]) -> PipelineContext:
        """Reconstruct a ``PipelineContext`` from a snapshot."""
        return cls.from_dict(snapshot)

    def build_stage_input(
        self,
        stage_name: str,
        stage_index: int,
        stage_total: int,
        pipeline_input: Any,
        runtime: dict[str, Any] | None = None,
        previous_deltas: list[dict[str, Any]] | None = None,
    ) -> Any:
        """Build an immutable stage input contract from current context state."""
        from src.core.contracts.pipeline_runtime import StageInput

        snapshot = {
            "result": self.result.to_dict(),
            "stage_status": dict(self.result.stage_status),
            "module_metrics": dict(self.result.module_metrics),
            "counts": {
                "subdomains": len(self.result.subdomains),
                "live_hosts": len(self.result.live_hosts),
                "urls": len(self.result.urls),
                "parameters": len(self.result.parameters),
                "reportable_findings": len(self.result.reportable_findings),
            },
        }
        return StageInput(
            stage_name=stage_name,
            stage_index=stage_index,
            stage_total=stage_total,
            pipeline=pipeline_input,
            state_snapshot=snapshot,
            runtime=runtime or {},
            previous_deltas=tuple(previous_deltas or []),
        )

    def build_stage_output(self, stage_name: str, duration_seconds: float) -> Any:
        """Build an immutable stage output contract from merged context state."""
        from src.core.contracts.pipeline_runtime import StageOutput

        state = str(self.result.stage_status.get(stage_name, StageStatus.COMPLETED.value))
        stage_metrics = self.result.module_metrics.get(stage_name, {})
        artifacts = {
            "reportable_findings": len(self.result.reportable_findings),
            "urls": len(self.result.urls),
            "live_hosts": len(self.result.live_hosts),
        }
        return StageOutput.from_stage_state(
            stage_name=stage_name,
            state=state,
            duration_seconds=duration_seconds,
            metrics=stage_metrics if isinstance(stage_metrics, dict) else {},
            artifacts=artifacts,
        )

    # ------------------------------------------------------------------
    # Typed property accessors — delegate to StageResult fields
    # ------------------------------------------------------------------

    @property
    def scope_entries(self) -> list[str]:
        return self.result.scope_entries

    @scope_entries.setter
    def scope_entries(self, value: list[str]) -> None:
        self.result.scope_entries = value

    @property
    def use_cache(self) -> bool:
        return self.result.use_cache

    @use_cache.setter
    def use_cache(self, value: bool) -> None:
        self.result.use_cache = value

    @property
    def module_metrics(self) -> dict[str, Any]:
        return self.result.module_metrics

    @property
    def previous_run(self) -> Path | None:
        return self.result.previous_run

    @previous_run.setter
    def previous_run(self, value: Path | None) -> None:
        self.result.previous_run = value

    @property
    def tool_status(self) -> dict[str, Any]:
        return self.result.tool_status

    @property
    def flow_manifest(self) -> dict[str, Any]:
        return self.result.flow_manifest

    @property
    def started_at(self) -> float:
        return self.result.started_at

    @property
    def discovery_enabled(self) -> bool:
        return self.result.discovery_enabled

    @discovery_enabled.setter
    def discovery_enabled(self, value: bool) -> None:
        self.result.discovery_enabled = value

    @property
    def subdomains(self) -> set[str]:
        return self.result.subdomains

    @subdomains.setter
    def subdomains(self, value: set[str]) -> None:
        self.result.subdomains = value

    @property
    def live_records(self) -> list[dict[str, Any]]:
        return self.result.live_records

    @live_records.setter
    def live_records(self, value: list[dict[str, Any]]) -> None:
        self.result.live_records = value

    @property
    def live_hosts(self) -> set[str]:
        return self.result.live_hosts

    @live_hosts.setter
    def live_hosts(self, value: set[str]) -> None:
        self.result.live_hosts = value

    @property
    def service_results(self) -> dict[str, Any]:
        return self.result.service_results

    @service_results.setter
    def service_results(self, value: dict[str, Any]) -> None:
        self.result.service_results = value

    @property
    def urls(self) -> set[str]:
        return self.result.urls

    @urls.setter
    def urls(self, value: set[str]) -> None:
        self.result.urls = value

    @property
    def url_stage_meta(self) -> dict[str, Any]:
        return self.result.url_stage_meta

    @url_stage_meta.setter
    def url_stage_meta(self, value: dict[str, Any]) -> None:
        self.result.url_stage_meta = value

    @property
    def parameters(self) -> set[str]:
        return self.result.parameters

    @parameters.setter
    def parameters(self, value: set[str]) -> None:
        self.result.parameters = value

    @property
    def target_profile(self) -> dict[str, Any]:
        return self.result.target_profile

    @target_profile.setter
    def target_profile(self, value: dict[str, Any]) -> None:
        self.result.target_profile = value

    @property
    def history_feedback(self) -> dict[str, Any]:
        return self.result.history_feedback

    @history_feedback.setter
    def history_feedback(self, value: dict[str, Any]) -> None:
        self.result.history_feedback = value

    @property
    def ranked_priority_urls(self) -> list[dict[str, Any]]:
        return self.result.ranked_priority_urls

    @ranked_priority_urls.setter
    def ranked_priority_urls(self, value: list[dict[str, Any]]) -> None:
        self.result.ranked_priority_urls = value

    @property
    def priority_urls(self) -> list[str]:
        return self.result.priority_urls

    @priority_urls.setter
    def priority_urls(self, value: list[str]) -> None:
        self.result.priority_urls = value

    @property
    def selected_priority_items(self) -> list[dict[str, Any]]:
        return self.result.selected_priority_items

    @selected_priority_items.setter
    def selected_priority_items(self, value: list[dict[str, Any]]) -> None:
        self.result.selected_priority_items = value

    @property
    def selection_meta(self) -> dict[str, Any]:
        return self.result.selection_meta

    @selection_meta.setter
    def selection_meta(self, value: dict[str, Any]) -> None:
        self.result.selection_meta = value

    @property
    def deep_analysis_urls(self) -> list[str]:
        return self.result.deep_analysis_urls

    @deep_analysis_urls.setter
    def deep_analysis_urls(self, value: list[str]) -> None:
        self.result.deep_analysis_urls = value

    @property
    def analysis_results(self) -> dict[str, list[dict[str, Any]]]:
        return self.result.analysis_results

    @analysis_results.setter
    def analysis_results(self, value: dict[str, list[dict[str, Any]]]) -> None:
        self.result.analysis_results = value

    @property
    def validation_runtime_inputs(self) -> dict[str, Any]:
        return self.result.validation_runtime_inputs

    @validation_runtime_inputs.setter
    def validation_runtime_inputs(self, value: dict[str, Any]) -> None:
        self.result.validation_runtime_inputs = value

    @property
    def validation_summary(self) -> dict[str, Any]:
        return self.result.validation_summary

    @validation_summary.setter
    def validation_summary(self, value: dict[str, Any]) -> None:
        self.result.validation_summary = value

    @property
    def campaign_summary(self) -> dict[str, Any]:
        return self.result.campaign_summary

    @campaign_summary.setter
    def campaign_summary(self, value: dict[str, Any]) -> None:
        self.result.campaign_summary = value

    @property
    def merged_findings(self) -> list[dict[str, Any]]:
        return self.result.merged_findings

    @merged_findings.setter
    def merged_findings(self, value: list[dict[str, Any]]) -> None:
        self.result.merged_findings = value

    @property
    def reportable_findings(self) -> list[dict[str, Any]]:
        return self.result.reportable_findings

    @reportable_findings.setter
    def reportable_findings(self, value: list[dict[str, Any]]) -> None:
        self.result.reportable_findings = value

    @property
    def iterative_stop_reason(self) -> str:
        return self.result.iterative_stop_reason

    @iterative_stop_reason.setter
    def iterative_stop_reason(self, value: str) -> None:
        self.result.iterative_stop_reason = value

    @property
    def executed_iterations(self) -> int:
        return self.result.executed_iterations

    @executed_iterations.setter
    def executed_iterations(self, value: int) -> None:
        self.result.executed_iterations = value

    @property
    def passive_scan_ok(self) -> bool:
        return self.result.passive_scan_ok

    @passive_scan_ok.setter
    def passive_scan_ok(self, value: bool) -> None:
        self.result.passive_scan_ok = value

    @property
    def validation_ok(self) -> bool:
        return self.result.validation_ok

    @validation_ok.setter
    def validation_ok(self, value: bool) -> None:
        self.result.validation_ok = value

    @property
    def screenshots(self) -> list[dict[str, Any]]:
        return self.result.screenshots

    @screenshots.setter
    def screenshots(self, value: list[dict[str, Any]]) -> None:
        self.result.screenshots = value

    @property
    def diff_summary(self) -> dict[str, Any]:
        return self.result.diff_summary

    @diff_summary.setter
    def diff_summary(self, value: dict[str, Any]) -> None:
        self.result.diff_summary = value

    @property
    def nuclei_findings(self) -> list[dict[str, Any]]:
        return self.result.nuclei_findings

    @nuclei_findings.setter
    def nuclei_findings(self, value: list[dict[str, Any]]) -> None:
        self.result.nuclei_findings = value

    @property
    def stage_status(self) -> dict[str, str]:
        return self.result.stage_status
