"""Unified orchestrator utilities.

Consolidates all helper functions previously spread across ``_orchestrator_helpers.py``,
``_state_helpers.py``, and the dead ``_helpers.py`` into a single, coherent module.

Sections:
* Stage baseline / stage method resolution    (from _orchestrator_helpers)
* Pipeline run finalisation                   (from _orchestrator_helpers)
* Stage timeout resolution                    (from _state_helpers)
* Stage output merge & WAL durability         (from _state_helpers)
* Checkpoint persistence & alert checking     (from _state_helpers)
* Stage-input contract builder                (from _state_helpers)
* Live-host timeout diagnostics               (from _state_helpers)
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Awaitable, Mapping, Sequence
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft7Validator
except ModuleNotFoundError:
    # Hard-fail fallback: instead of silently passing malformed data, we
    # raise on the first use. Previously the no-op validator allowed
    # corrupted stage outputs to propagate undetected through the
    # pipeline, breaking the contract-enforcement story. Operators must
    # either install ``jsonschema`` or set ``PIPELINE_ALLOW_NO_SCHEMA=1``
    # to explicitly opt out (with a loud warning).
    import os as _os

    class Draft7Validator:  # type: ignore[no-redef]
        """Strict fallback for environments without jsonschema."""

        class _DisabledValidationError(RuntimeError):
            pass

        class TypeChecker:
            @staticmethod
            def redefine(_key: str, message: str) -> Any:
                return type("ValidationError", (), {"path": (), "message": message})()

        def __init__(self, _schema: dict[str, Any]) -> None:
            self._schema = _schema

        def iter_errors(self, _payload: Any) -> list[Any]:
            if _os.environ.get("PIPELINE_ALLOW_NO_SCHEMA", "").lower() in {"1", "true", "yes"}:
                return []
            raise self._DisabledValidationError(
                "jsonschema is not installed and PIPELINE_ALLOW_NO_SCHEMA is not set; "
                "refusing to validate. Install the 'jsonschema' package to restore "
                "StageOutput/finding contract enforcement."
            )


_JSONSCHEMA_MISSING_LOGGED = False


def install_jsonschema_warning() -> None:
    """Log (once) a warning that schema validation is bypassed.

    Called from the schema-builder entry points so operators notice the
    degraded state on startup instead of after a malformed payload silently
    propagates through the pipeline.
    """
    global _JSONSCHEMA_MISSING_LOGGED
    if _JSONSCHEMA_MISSING_LOGGED:
        return
    _JSONSCHEMA_MISSING_LOGGED = True
    import logging as _logging

    if _os.environ.get("PIPELINE_ALLOW_NO_SCHEMA", "").lower() in {"1", "true", "yes"}:
        _logging.getLogger(__name__).warning(
            "jsonschema is not installed and PIPELINE_ALLOW_NO_SCHEMA=1; "
            "StageOutput/finding contract validation is DISABLED. "
            "Install the 'jsonschema' package to restore schema enforcement."
        )


from src.core.contracts.pipeline_runtime import PipelineInput, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus
from src.infrastructure.observability.alerts import get_alert_rule_checker
from src.pipeline.constants.progress import _STAGE_BASELINE_PROGRESS

from .._constants import STAGE_ORDER, STAGE_ORDER_INDEX, STAGE_TIMEOUTS
from .security import CHECKPOINT_CURRENT_VERSION

logger = get_pipeline_logger(__name__)

# ---------------------------------------------------------------------------
# Legacy stage attribute map (for monkeypatch seams in tests)
# ---------------------------------------------------------------------------

from src.pipeline.services.stage_registry import LEGACY_STAGE_ATTRS

# ---------------------------------------------------------------------------
# Timeout constants
# ---------------------------------------------------------------------------

SUBDOMAIN_COUNT_WARNING = 8000
HOST_COUNT_WARNING = 4000
MAXIMUM_URLS_PER_HOST = 1500
DEFAULT_BATCH_SIZE = 400
PROBE_TIME_MULTIPLIER = 1.35
PROBE_TIME_BUFFER_SECONDS = 300
ACCESS_CONTROL_CANDIDATE_THRESHOLD = 150
LIVE_HOST_COUNT_WARNING = 2500
LIVE_HOST_COUNT_LOW = 1200
LIVE_HOST_COUNT_HIGH = 600
SCOPE_ENTRY_THRESHOLD = 1200

# ---------------------------------------------------------------------------
# Stage baseline
# ---------------------------------------------------------------------------


def stage_baseline(stage_name: str, stage_order: Sequence[str]) -> int:
    """Compute the baseline progress percentage for a given stage.

    Uses a predefined map of known stages for accurate percentages based on
    empirical pipeline timing data. Falls back to proportional calculation
    for unknown stages based on their position in the stage order.
    """
    if stage_name in _STAGE_BASELINE_PROGRESS:
        return _STAGE_BASELINE_PROGRESS[stage_name]
    idx = STAGE_ORDER_INDEX.get(stage_name)
    if idx is not None:
        return int(((idx + 1) / max(1, len(STAGE_ORDER))) * 100)
    return 0


# ---------------------------------------------------------------------------
# Stage method resolution
# ---------------------------------------------------------------------------


def build_stage_methods_map(
    *,
    stage_order: Sequence[str],
    module_globals: dict[str, Any],
    resolve_stage_runner_func: Any,
) -> dict[str, Any]:
    """Resolve concrete stage callables while preserving legacy monkeypatch seams."""
    stage_methods: dict[str, Any] = {}
    for stage_name in stage_order:
        legacy_attr = LEGACY_STAGE_ATTRS.get(stage_name, "")
        legacy_runner = module_globals.get(legacy_attr) if legacy_attr else None
        if callable(legacy_runner):
            stage_methods[stage_name] = legacy_runner
            continue
        try:
            stage_methods[stage_name] = resolve_stage_runner_func(stage_name)
        except KeyError as exc:
            logger.warning("Failed to resolve stage runner for stage '%s': %s", stage_name, exc)
            continue
    return stage_methods


# ---------------------------------------------------------------------------
# Pipeline run finalisation
# ---------------------------------------------------------------------------


async def finalize_run(
    *,
    event_bus: Any,
    exit_code: int,
    logger_obj: logging.Logger,
) -> int:
    """Drain async side effects and perform best-effort HTTP client cleanup."""
    try:
        flush_pending: Awaitable[Any] = event_bus.flush_pending(timeout=10.0)
        await flush_pending
    except Exception:
        logger_obj.warning("Failed to flush pending event handlers", exc_info=True)

    try:
        from src.core.http_utils import close_all_clients

        await close_all_clients()
    except Exception:
        logger_obj.debug("Best-effort AsyncClient cleanup failed", exc_info=True)

    try:
        event_bus.clear()
    except Exception:
        logger_obj.warning("Failed to clear event bus subscriptions", exc_info=True)

    try:
        from src.core.events import reset_event_bus

        reset_event_bus()
    except Exception as exc:
        logger_obj.warning("Failed to reset event bus: %s", exc, exc_info=True)

    return exit_code


# ---------------------------------------------------------------------------
# Stage-output schema validation (private)
# ---------------------------------------------------------------------------


class StageOutputValidationError(ValueError):
    """Raised when a StageOutput fails strict schema validation before merge."""


_stage_output_validator_instance: Draft7Validator | None = None
_finding_validator_instance: Draft7Validator | None = None


class _NoOpValidator:
    def iter_errors(self, instance: Any) -> Any:
        return []


def _stage_output_schema_validator() -> Draft7Validator:
    global _stage_output_validator_instance
    if _stage_output_validator_instance is None:
        schema_path = None
        current = Path(__file__).resolve().parent
        for _ in range(8):
            candidate = current / ".ai" / "schemas" / "stage_output.schema.json"
            if candidate.exists():
                schema_path = candidate
                break
            if current.parent == current:
                break
            current = current.parent

        if schema_path is None:
            try:
                candidate = (
                    Path(__file__).resolve().parents[5]
                    / ".ai"
                    / "schemas"
                    / "stage_output.schema.json"
                )
                if candidate.exists():
                    schema_path = candidate
            except IndexError as exc:
                logger.warning("Operation failed in utils.py: %s", exc, exc_info=True)  # noqa: BLE001

        if schema_path is None or not schema_path.exists():
            logger.warning(
                "Schema file 'stage_output.schema.json' not found. Stage output validation will be bypassed."
            )
            return _NoOpValidator()  # type: ignore[return-value]

        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            _stage_output_validator_instance = Draft7Validator(schema)
        except Exception as exc:
            logger.error("Failed to load schema JSON from %s: %s", schema_path, exc)
            return _NoOpValidator()  # type: ignore[return-value]
    if isinstance(_stage_output_validator_instance, _NoOpValidator):
        install_jsonschema_warning()
    return _stage_output_validator_instance


def _finding_schema_validator() -> Draft7Validator:
    global _finding_validator_instance
    if _finding_validator_instance is None:
        schema_path = None
        current = Path(__file__).resolve().parent
        for _ in range(8):
            candidate = current / ".ai" / "schemas" / "finding.schema.json"
            if candidate.exists():
                schema_path = candidate
                break
            if current.parent == current:
                break
            current = current.parent

        if schema_path is None:
            try:
                candidate = (
                    Path(__file__).resolve().parents[5] / ".ai" / "schemas" / "finding.schema.json"
                )
                if candidate.exists():
                    schema_path = candidate
            except IndexError as exc:
                logger.warning("Operation failed in utils.py: %s", exc, exc_info=True)  # noqa: BLE001

        if schema_path is None or not schema_path.exists():
            logger.warning(
                "Schema file 'finding.schema.json' not found. Finding schema validation will be bypassed."
            )
            return _NoOpValidator()  # type: ignore[return-value]

        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            _finding_validator_instance = Draft7Validator(schema)
        except Exception as exc:
            logger.error("Failed to load finding schema JSON from %s: %s", schema_path, exc)
            return _NoOpValidator()  # type: ignore[return-value]
    if isinstance(_finding_validator_instance, _NoOpValidator):
        install_jsonschema_warning()
    return _finding_validator_instance


def _validate_stage_output_contract(stage_name: str, stage_output: StageOutput) -> None:
    """Validate the full StageOutput contract and deep-validate critical state keys."""
    payload = stage_output.to_dict()
    errors = list(_stage_output_schema_validator().iter_errors(payload))

    state_delta = payload.get("state_delta", {})
    finding_keys = {"findings", "merged_findings", "reportable_findings", "vulnerabilities"}

    for key in finding_keys:
        items = state_delta.get(key)
        if isinstance(items, (list, tuple)):
            validator = _finding_schema_validator()
            for i, item in enumerate(items):
                if not isinstance(item, dict):
                    errors.append(
                        Draft7Validator.TypeChecker.redefine(
                            key, f"Item {i} in '{key}' must be a dict"
                        )
                    )
                    continue
                for error in validator.iter_errors(item):
                    error.message = f"In {key}[{i}]: {error.message}"
                    errors.append(error)

    if not errors:
        return

    details = "; ".join(
        f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
        for error in sorted(errors, key=lambda e: str(e.path))
    )
    raise StageOutputValidationError(f"Stage '{stage_name}' contract violation: {details}")


# ---------------------------------------------------------------------------
# Stage timeout resolution
# ---------------------------------------------------------------------------


def coerce_positive_int(value: Any) -> int | None:
    """Coerce value to a positive integer, returning None if invalid."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


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
        override = coerce_positive_int(stage_overrides.get(stage_name))
        if override is not None:
            return int(override)

    direct_override = coerce_positive_int(filters.get(f"{stage_name}_stage_timeout_seconds"))
    if direct_override is not None:
        return int(direct_override)

    if stage_name == "live_hosts":
        subdomains_attr = getattr(ctx.result, "subdomains", None)
        subdomain_count = len(subdomains_attr) if subdomains_attr is not None else 0
        if subdomains_attr is None:
            logger.debug(
                "compute_stage_timeout: ctx.result.subdomains is None (stage=%s)", stage_name
            )
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
            batch_size = max(
                100, int(httpx_cfg.get("batch_size", DEFAULT_BATCH_SIZE) or DEFAULT_BATCH_SIZE)
            )
            batch_concurrency = max(1, int(httpx_cfg.get("batch_concurrency", 1) or 1))
            per_batch_timeout = max(10, int(httpx_cfg.get("timeout_seconds", 120) or 120))

            total_batches = max(1, (candidate_count + batch_size - 1) // batch_size)
            estimated_probe_seconds = (
                ((total_batches + batch_concurrency - 1) // batch_concurrency)
                * per_batch_timeout
                * retry_attempts
            )
            estimated_total_seconds = (
                int(estimated_probe_seconds * PROBE_TIME_MULTIPLIER) + PROBE_TIME_BUFFER_SECONDS
            )
            base_timeout = max(base_timeout, min(7200, estimated_total_seconds))

        return base_timeout

    if stage_name == "access_control":
        selected_priority_items = list(getattr(ctx.result, "selected_priority_items", []) or [])
        urls_attr = getattr(ctx.result, "urls", None)
        if urls_attr is None or not isinstance(urls_attr, (set, list, tuple)):
            logger.debug(
                "compute_stage_timeout: ctx.result.urls is %s=%r (stage=%s); defaulting to empty set",
                type(urls_attr).__name__,
                urls_attr,
                stage_name,
            )
            urls = set()
        else:
            urls = set(urls_attr)
        candidate_count = max(len(selected_priority_items), len(urls))
        if candidate_count >= ACCESS_CONTROL_CANDIDATE_THRESHOLD:
            return max(base_timeout, 1500)
        if candidate_count >= 60:
            return max(base_timeout, 900)
        return base_timeout

    if stage_name != "urls":
        return base_timeout

    live_hosts_attr = getattr(ctx.result, "live_hosts", None)
    live_host_count = len(live_hosts_attr) if live_hosts_attr is not None else 0
    if live_hosts_attr is None:
        logger.debug("compute_stage_timeout: ctx.result.live_hosts is None (stage=%s)", stage_name)
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


# ---------------------------------------------------------------------------
# Live-host timeout diagnostics
# ---------------------------------------------------------------------------


def log_live_hosts_timeout_diagnostics(
    ctx: PipelineContext,
    timeout: int,
) -> None:
    """Emit stack diagnostics when the live-host stage times out."""
    try:
        import sys
        import threading
        import traceback

        subdomains_attr = getattr(ctx.result, "subdomains", None)
        subdomain_count = len(subdomains_attr) if subdomains_attr is not None else 0
        live_hosts_attr = getattr(ctx.result, "live_hosts", None)
        live_host_count = len(live_hosts_attr) if live_hosts_attr is not None else 0

        logger.error(
            "Live-host timeout diagnostics: timeout=%ss subdomains=%d live_records=%d live_hosts=%d",
            timeout,
            subdomain_count,
            len(getattr(ctx.result, "live_records", []) or []),
            live_host_count,
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


# ---------------------------------------------------------------------------
# Stage-output merge
# ---------------------------------------------------------------------------


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

    _validate_stage_output_contract(stage_name, stage_output)
    state_delta = _to_mutable(dict(stage_output.state_delta))
    validation_errors = GLOBAL_STATE_SCHEMA_REGISTRY.validate_delta(state_delta)
    if validation_errors:
        raise StageOutputValidationError(
            f"Stage '{stage_name}' produced invalid state_delta: " + "; ".join(validation_errors)
        )

    if wal:
        wal_id = wal.log_delta(stage_name, state_delta)
        if not wal_id:
            raise RuntimeError(
                f"WAL durability layer failed for stage '{stage_name}': no durable backend accepted record."
            )
        if hasattr(ctx.result, "_neural_state"):
            state_delta = dict(state_delta)
            state_delta["_wal_id"] = wal_id
            ctx.result._neural_state.last_wal_id = wal_id

    ctx.result.apply_state_delta(state_delta)

    if hasattr(ctx.result.stage_status, "copy"):
        ctx.result.stage_status = dict(ctx.result.stage_status)
    if stage_output.outcome.value == "failed":
        ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
    elif stage_output.outcome.value == "skipped":
        ctx.result.stage_status[stage_name] = StageStatus.SKIPPED.value
    else:
        ctx.result.stage_status[stage_name] = StageStatus.COMPLETED.value

    existing_metrics = ctx.result.module_metrics.get(stage_name) or {}
    stage_metrics = _to_mutable(dict(stage_output.metrics))
    merged_metrics = {}
    if isinstance(existing_metrics, dict):
        merged_metrics.update(_to_mutable(existing_metrics))
    merged_metrics.update(stage_metrics)

    merged_metrics.setdefault("status", stage_output.outcome.value)
    merged_metrics.setdefault("duration_seconds", round(stage_output.duration_seconds, 2))
    if stage_output.reason:
        merged_metrics.setdefault("reason", stage_output.reason)
    if stage_output.error:
        merged_metrics.setdefault("error", stage_output.error)
    if hasattr(ctx.result.module_metrics, "copy"):
        ctx.result.module_metrics = dict(ctx.result.module_metrics)
    ctx.result.module_metrics[stage_name] = merged_metrics

    if stage_name == "parameters":
        ctx.output_store.write_parameters(ctx.result.parameters)
    elif stage_name == "ranking":
        ctx.output_store.write_priority_endpoints(ctx.result.priority_urls)


# ---------------------------------------------------------------------------
# Checkpoint utilities
# ---------------------------------------------------------------------------


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

        getrusage = getattr(resource, "getrusage", None)
        rusage_self = getattr(resource, "RUSAGE_SELF", None)
        if getrusage is not None and rusage_self is not None:
            mem_usage = getrusage(rusage_self).ru_maxrss / 1024
            ctx.result.module_metrics.setdefault(stage_name, {})["memory_mb"] = round(mem_usage, 1)
    except (ImportError, AttributeError) as exc:
        logger.warning("Operation failed in utils.py: %s", exc, exc_info=True)  # noqa: BLE001

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
            # Stamp the checkpoint version so recovery can reject
            # incompatible payloads (see ``security.run_secured``).
            snapshot = dict(ctx.to_dict())
            snapshot["checkpoint_version"] = CHECKPOINT_CURRENT_VERSION
            checkpoint_mgr.save_context_snapshot(stage_name, snapshot)
        else:
            checkpoint_dir = Path(checkpoint_mgr.checkpoint_dir)
            (checkpoint_dir / stage_name).parent.mkdir(parents=True, exist_ok=True)
            target = checkpoint_dir / f"{stage_name}.json"
            # Atomic write: serialize to a sibling tmp file then ``os.replace``
            # onto the real path. The previous implementation called
            # ``Path.write_text`` directly which could leave a truncated
            # file on a crash, breaking the next ``attempt_recovery``.
            tmp = target.with_suffix(target.suffix + ".tmp")
            snapshot = dict(ctx.to_dict())
            snapshot["checkpoint_version"] = CHECKPOINT_CURRENT_VERSION
            payload = json.dumps(snapshot, default=str)
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError as exc:
                    logger.warning("Operation failed in utils.py: %s", exc, exc_info=True)  # noqa: BLE001
            os.replace(tmp, target)
    except (OSError, TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.warning("Failed to persist checkpoint for stage %s: %s", stage_name, exc)


# ---------------------------------------------------------------------------
# Stage-input contract builder
# ---------------------------------------------------------------------------


def build_stage_input_contract(
    orchestrator: Any,
    stage_name: str,
    ctx: PipelineContext,
    config: Any | None = None,
) -> dict[str, Any]:
    stage_index = (STAGE_ORDER_INDEX.get(stage_name, -1) + 1) if stage_name in STAGE_ORDER_INDEX else 0
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
