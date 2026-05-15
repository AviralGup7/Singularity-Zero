import json
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from src.core.contracts.pipeline_runtime import PipelineInput, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus
from src.infrastructure.observability.alerts import get_alert_rule_checker

from ._constants import STAGE_ORDER, STAGE_TIMEOUTS

logger = get_pipeline_logger(__name__)


# Thresholds for adaptive timeout calculation
# These values trigger extended timeouts for large-scale scans
SUBDOMAIN_COUNT_WARNING = 8000
HOST_COUNT_WARNING = 4000
MAXIMUM_URLS_PER_HOST = 1500

# Default batch processing settings for httpx probing
DEFAULT_BATCH_SIZE = 400

# Timeout estimation multipliers
# Applied to estimated probe duration to account for network variance
PROBE_TIME_MULTIPLIER = 1.35
# Buffer seconds added to estimated time for safety margin
PROBE_TIME_BUFFER_SECONDS = 300

# Count thresholds for various stage timeout extensions
# access_control: minimum candidates to warrant extended timeout
ACCESS_CONTROL_CANDIDATE_THRESHOLD = 150
# urls stage: live host count thresholds for progressive timeout extension
LIVE_HOST_COUNT_WARNING = 2500
LIVE_HOST_COUNT_LOW = 1200
LIVE_HOST_COUNT_HIGH = 600
# urls stage: scope entries requiring extended timeout
SCOPE_ENTRY_THRESHOLD = 1200


class StageOutputValidationError(ValueError):
    """Raised when a StageOutput fails strict schema validation before merge."""


@lru_cache(maxsize=1)
def _stage_output_schema_validator() -> Draft7Validator:
    schema_path = Path(__file__).resolve().parents[4] / ".ai" / "schemas" / "stage_output.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)
    return validator


@lru_cache(maxsize=1)
def _finding_schema_validator() -> Draft7Validator:
    schema_path = Path(__file__).resolve().parents[4] / ".ai" / "schemas" / "finding.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft7Validator(schema)
    return validator


def _validate_stage_output_contract(stage_name: str, stage_output: StageOutput) -> None:
    """Validate the full StageOutput contract and deep-validate critical state keys."""
    payload = stage_output.to_dict()

    # 1. Top-level contract validation
    errors = list(_stage_output_schema_validator().iter_errors(payload))

    # 2. Deep validation for findings-related keys in state_delta
    state_delta = payload.get("state_delta", {})
    finding_keys = {"findings", "merged_findings", "reportable_findings", "vulnerabilities"}

    for key in finding_keys:
        items = state_delta.get(key)
        if isinstance(items, (list, tuple)):
            validator = _finding_schema_validator()
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    errors.append(Draft7Validator.TYPE_CHECKER.redefine(key, f"Item {i} in '{key}' must be a dict"))
                    continue
                for error in validator.iter_errors(item):
                    # Wrap the error with path context
                    error.message = f"In {key}[{i}]: {error.message}"
                    errors.append(error)

    if not errors:
        return

    details = "; ".join(
        f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
        for error in sorted(errors, key=lambda e: str(e.path))
    )
    raise StageOutputValidationError(
        f"Stage '{stage_name}' contract violation: {details}"
    )


def resolve_stage_timeout(
    orchestrator: Any,
    stage_name: str,
    config: Any,
    ctx: PipelineContext,
) -> int:
    base_timeout = int(STAGE_TIMEOUTS.get(stage_name, 600) or 600)

    filters = getattr(config, "filters", {}) if config is not None else {}
    if not isinstance(filters, dict):
        filters = {}

    stage_overrides = filters.get("stage_timeout_overrides", {})
    if isinstance(stage_overrides, dict):
        override = orchestrator._coerce_positive_int(stage_overrides.get(stage_name))
        if override is not None:
            return int(override)

    direct_override = orchestrator._coerce_positive_int(
        filters.get(f"{stage_name}_stage_timeout_seconds")
    )
    if direct_override is not None:
        return int(direct_override)

    if stage_name == "live_hosts":
        subdomain_count = len(getattr(ctx.result, "subdomains", set()) or set())
        scope_entry_count = len(getattr(ctx.result, "scope_entries", []) or [])
        candidate_count = max(subdomain_count, scope_entry_count)

        if candidate_count >= SUBDOMAIN_COUNT_WARNING:
            base_timeout = max(base_timeout, 3600)
        elif candidate_count >= HOST_COUNT_WARNING:
            base_timeout = max(base_timeout, 2400)
        elif candidate_count >= MAXIMUM_URLS_PER_HOST:
            base_timeout = max(base_timeout, 1500)

        tools_cfg = getattr(config, "tools", {}) if config is not None else {}
        if not isinstance(tools_cfg, dict):
            tools_cfg = {}
        httpx_cfg = getattr(config, "httpx", {}) if config is not None else {}
        if not isinstance(httpx_cfg, dict):
            httpx_cfg = {}
        retry_attempts = max(1, int(tools_cfg.get("retry_attempts", 1) or 1))

        if bool(tools_cfg.get("httpx")) and candidate_count > 0:
            batch_size = max(100, int(httpx_cfg.get("batch_size", DEFAULT_BATCH_SIZE) or DEFAULT_BATCH_SIZE))
            batch_concurrency = max(1, int(httpx_cfg.get("batch_concurrency", 1) or 1))
            per_batch_timeout = max(10, int(httpx_cfg.get("timeout_seconds", 120) or 120))

            total_batches = max(1, (candidate_count + batch_size - 1) // batch_size)
            estimated_probe_seconds = (
                ((total_batches + batch_concurrency - 1) // batch_concurrency)
                * per_batch_timeout
                * retry_attempts
            )
            estimated_total_seconds = int(estimated_probe_seconds * PROBE_TIME_MULTIPLIER) + PROBE_TIME_BUFFER_SECONDS
            base_timeout = max(base_timeout, min(7200, estimated_total_seconds))

        return base_timeout

    if stage_name == "access_control":
        selected_priority_items = list(getattr(ctx.result, "selected_priority_items", []) or [])
        urls: set[str] = getattr(ctx.result, "urls", set()) or set()
        candidate_count = max(len(selected_priority_items), len(urls))
        if candidate_count >= ACCESS_CONTROL_CANDIDATE_THRESHOLD:
            return max(base_timeout, 1500)
        if candidate_count >= 60:
            return max(base_timeout, 900)
        return base_timeout

    if stage_name != "urls":
        return base_timeout

    live_host_count = len(getattr(ctx.result, "live_hosts", set()) or set())
    scope_entry_count = len(getattr(ctx.result, "scope_entries", []) or [])

    if live_host_count >= LIVE_HOST_COUNT_WARNING:
        return max(base_timeout, 2400)
    if live_host_count >= LIVE_HOST_COUNT_LOW:
        return max(base_timeout, 1800)
    if live_host_count >= LIVE_HOST_COUNT_HIGH:
        return max(base_timeout, 1200)
    if live_host_count == 0 and scope_entry_count >= SCOPE_ENTRY_THRESHOLD:
        return max(base_timeout, 1200)
    return base_timeout


def log_live_hosts_timeout_diagnostics(
    ctx: PipelineContext,
    timeout: int,
) -> None:
    """Emit stack diagnostics when the live-host stage times out."""
    try:
        import sys
        import threading
        import traceback

        logger.error(
            "Live-host timeout diagnostics: timeout=%ss subdomains=%d live_records=%d live_hosts=%d",
            timeout,
            len(getattr(ctx.result, "subdomains", set()) or set()),
            len(getattr(ctx.result, "live_records", []) or []),
            len(getattr(ctx.result, "live_hosts", set()) or set()),
        )

        frames = sys._current_frames()
        dumped = 0
        for thread in threading.enumerate():
            if thread.ident is None:
                continue
            if thread.name != "MainThread" and not (
                thread.name.startswith("asyncio") or "ThreadPoolExecutor" in thread.name
            ):
                continue
            frame = frames.get(thread.ident)
            if frame is None:
                continue
            stack_lines = traceback.format_stack(frame)
            stack_tail = "".join(stack_lines[-25:])
            logger.error(
                "Live-host timeout thread stack [%s/%s]:\n%s",
                thread.name,
                thread.ident,
                stack_tail,
            )
            dumped += 1
            if dumped >= 12:
                break
    except (OSError, AttributeError, RuntimeError) as exc:
        logger.warning("Failed to capture live-host timeout diagnostics: %s", exc)


def build_stage_input_contract(
    orchestrator: Any,
    stage_name: str,
    ctx: PipelineContext,
    config: Any | None = None,
) -> dict[str, Any]:
    stage_index = (STAGE_ORDER.index(stage_name) + 1) if stage_name in STAGE_ORDER else 0
    if orchestrator._pipeline_input is None:
        orchestrator._pipeline_input = PipelineInput(
            target_name="unknown",
            scope_entries=tuple(ctx.result.scope_entries),
            run_id=orchestrator._pipeline_correlation_id or "runtime",
            metadata={
                "flow_stage_count": len(STAGE_ORDER),
            },
        )
    stage_input = ctx.build_stage_input(
        stage_name=stage_name,
        stage_index=stage_index,
        stage_total=len(STAGE_ORDER),
        pipeline_input=orchestrator._pipeline_input,
        runtime={
            "mode": str(getattr(config, "mode", "default") or "default") if config else "default",
            "filters": dict(getattr(config, "filters", {}) or {}) if config else {},
            "analysis": dict(getattr(config, "analysis", {}) or {}) if config else {},
            "scoring": dict(getattr(config, "scoring", {}) or {}) if config else {},
        },
    )
    from typing import cast
    return cast(dict[str, Any], stage_input.to_dict())


def merge_stage_output(
    ctx: PipelineContext,
    stage_name: str,
    stage_output: StageOutput,
    wal: Any | None = None,
) -> None:
    """Merge immutable stage output into mutable pipeline context with WAL durability."""
    from src.core.contracts.state_schema import GLOBAL_STATE_SCHEMA_REGISTRY

    def _to_mutable(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {k: _to_mutable(v) for k, v in value.items()}
        if isinstance(value, (tuple, list, set, frozenset)):
            return [_to_mutable(item) for item in value]
        return value

    # Phase 1: Strict contract and state-delta validation before mutating context.
    _validate_stage_output_contract(stage_name, stage_output)
    state_delta = dict(stage_output.state_delta)
    validation_errors = GLOBAL_STATE_SCHEMA_REGISTRY.validate_delta(state_delta)
    if validation_errors:
        raise StageOutputValidationError(
            f"Stage '{stage_name}' produced invalid state_delta: "
            + "; ".join(validation_errors)
        )

    # Phase 2: Frontier Durability - Log to WAL before applying
    if wal:
        wal.log_delta(stage_name, state_delta)

    # Use the new CRDT-aware merge logic in ctx.result
    ctx.result.apply_state_delta(state_delta)

    if stage_output.outcome.value == "failed":
        ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
    elif stage_output.outcome.value == "skipped":
        ctx.result.stage_status[stage_name] = StageStatus.SKIPPED.value
    else:
        ctx.result.stage_status[stage_name] = StageStatus.COMPLETED.value

    stage_metrics = _to_mutable(dict(stage_output.metrics))
    stage_metrics.setdefault("status", stage_output.outcome.value)
    stage_metrics.setdefault("duration_seconds", round(stage_output.duration_seconds, 2))
    if stage_output.reason:
        stage_metrics.setdefault("reason", stage_output.reason)
    if stage_output.error:
        stage_metrics.setdefault("error", stage_output.error)
    ctx.result.module_metrics[stage_name] = stage_metrics

    if stage_name == "parameters":
        ctx.output_store.write_parameters(ctx.result.parameters)
    elif stage_name == "ranking":
        ctx.output_store.write_priority_endpoints(ctx.result.priority_urls)


def safe_checkpoint_stage_outcome(
    checkpoint_mgr: Any,
    stage_name: str,
    stage_state: str,
    stage_metrics: Any,
) -> None:
    """Persist stage outcome when checkpoint manager supports explicit outcomes."""
    if not hasattr(checkpoint_mgr, "mark_stage_outcome"):
        return

    normalized_state = str(stage_state or "").strip().upper()
    if normalized_state == StageStatus.FAILED.value:
        outcome = "failed"
    elif normalized_state == StageStatus.SKIPPED.value:
        outcome = "skipped"
    else:
        outcome = "completed"

    payload: dict[str, Any] = {"status": outcome}
    if isinstance(stage_metrics, dict):
        for key in (
            "reason",
            "error",
            "failure_reason",
            "failure_reason_code",
            "retry_count",
            "duration_seconds",
            "details",
        ):
            value = stage_metrics.get(key)
            if value is not None:
                payload[key] = value

    error = ""
    if isinstance(stage_metrics, dict):
        error = str(
            stage_metrics.get("failure_reason")
            or stage_metrics.get("error")
            or stage_metrics.get("reason")
            or ""
        ).strip()
    checkpoint_mgr.mark_stage_outcome(
        stage_name,
        outcome,
        error=error,
        result=payload,
    )


async def record_stage_post_run(
    stage_name: str,
    ctx: PipelineContext,
    checkpoint_mgr: Any,
) -> None:
    """Record post-stage metrics, alerts, and checkpoint persistence."""
    try:
        import resource

        mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        ctx.result.module_metrics.setdefault(stage_name, {})["memory_mb"] = round(mem_usage, 1)
    except (ImportError, AttributeError):
        pass

    try:
        alert_checker = get_alert_rule_checker()
        alerts = alert_checker.check_rules(stage_name, ctx.result.to_dict())
        if alerts:
            logger.info(
                "%d pipeline alert(s) triggered after stage %s",
                len(alerts),
                stage_name,
            )
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.warning("Alert rule checking failed after stage %s: %s", stage_name, exc)

    try:
        if hasattr(checkpoint_mgr, "save_context_snapshot"):
            checkpoint_mgr.save_context_snapshot(stage_name, ctx.to_dict())
        else:
            checkpoint_dir = checkpoint_mgr.checkpoint_dir
            (checkpoint_dir / stage_name).parent.mkdir(parents=True, exist_ok=True)
            (checkpoint_dir / f"{stage_name}.json").write_text(
                json.dumps(ctx.to_dict(), default=str)
            )
    except (OSError, TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.warning("Failed to persist checkpoint for stage %s: %s", stage_name, exc)
