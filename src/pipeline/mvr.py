"""Maximum Viable Result (MVR): degrade, don't die.

Safe-by-default flags that keep a scan producing findings/reports when
non-critical stages, tools, disk, or authority fail. Critical
``must_succeed`` stages still fail-closed for their dependents.
"""

from __future__ import annotations

import atexit
import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

MVR_ENABLED_ENV = "MVR_ENABLED"
CONTINUE_ON_NON_CRITICAL_ENV = "PIPELINE_CONTINUE_ON_NON_CRITICAL"
STRICT_CRITICAL_ENV = "PIPELINE_STRICT_CRITICAL"
EMIT_PARTIAL_ENV = "REPORT_EMIT_PARTIAL_ON_SHUTDOWN"


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def mvr_enabled() -> bool:
    return _env_flag(MVR_ENABLED_ENV, True)


def continue_on_non_critical() -> bool:
    return mvr_enabled() and _env_flag(CONTINUE_ON_NON_CRITICAL_ENV, True)


def strict_critical() -> bool:
    return _env_flag(STRICT_CRITICAL_ENV, False)


def emit_partial_on_shutdown() -> bool:
    return mvr_enabled() and _env_flag(EMIT_PARTIAL_ENV, True)


@dataclass(frozen=True, slots=True)
class StagePolicy:
    """Persisted per-node survival policy (frozen with the graph)."""

    critical: bool = False
    must_succeed: bool = False
    allow_degraded_downstream: bool = True


def stage_policy_of(node: Any) -> StagePolicy:
    return StagePolicy(
        critical=bool(getattr(node, "critical", False)),
        must_succeed=bool(getattr(node, "must_succeed", False)),
        allow_degraded_downstream=bool(getattr(node, "allow_degraded_downstream", True)),
    )


def abort_on_stage_failure(node: Any) -> bool:
    """True only when this failure must stop *new* independent work.

    Default MVR: non-critical (and critical-without-must_succeed) failures
    become DEGRADED and the DAG continues. ``PIPELINE_CONTINUE_ON_NON_CRITICAL=false``
    restores fail-fast. ``PIPELINE_STRICT_CRITICAL=true`` treats every
    ``critical=True`` node as must-succeed.
    """
    if not continue_on_non_critical():
        return True
    policy = stage_policy_of(node)
    if policy.must_succeed:
        return True
    if strict_critical() and policy.critical:
        return True
    return False


_binder: dict[str, Any] | None = None
_atexit_registered = False
_partial_emitted = False


def bind_run(
    *,
    run_id: str,
    output_dir: str | os.PathLike[str] | None,
    ctx: Any | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Remember the in-flight run so SIGINT/OOM can emit a partial report."""
    global _binder, _atexit_registered, _partial_emitted
    _partial_emitted = False
    _binder = {
        "run_id": str(run_id or ""),
        "output_dir": str(output_dir or ""),
        "ctx": ctx,
        "extra": dict(extra or {}),
    }
    if not _atexit_registered:
        atexit.register(lambda: emit_bound_partial_report("atexit"))
        _atexit_registered = True


def current_run() -> dict[str, Any] | None:
    return _binder


def unbind_run() -> None:
    global _binder
    _binder = None


def emit_bound_partial_report(reason: str) -> int:
    """Best-effort partial report from the bound run. Returns findings written."""
    global _partial_emitted
    if not emit_partial_on_shutdown():
        return 0
    if _partial_emitted:
        return 0
    state = current_run()
    if not state:
        return 0
    try:
        from src.reporting.partial import emit_partial_report

        ctx = state.get("ctx")
        result = emit_partial_report(
            run_id=str(state.get("run_id") or "unknown"),
            output_dir=state.get("output_dir") or None,
            reason=reason,
            ctx=ctx,
        )
        _partial_emitted = True
        return int(result.findings_emitted)
    except Exception as exc:  # noqa: BLE001
        logger.warning("partial report on %s failed: %s", reason, exc)
        return 0


def finalize_crashed_runs(output_dir: str | os.PathLike[str] | None) -> int:
    """Emit partial reports for CRASHED_IN_PROGRESS DAG checkpoints.

    Honors ``AUTO_FINALIZE_CRASHED_ON_STARTUP``. Lives in the pipeline
    layer so ``src/core`` stays free of ``src.reporting`` imports.
    """
    if not output_dir:
        return 0
    from src.core.checkpoint.dag_checkpoint import auto_finalize_crashed, detect_crashed_runs

    if not auto_finalize_crashed():
        return 0
    written = 0
    try:
        from src.reporting.partial import emit_partial_report
    except Exception as exc:  # noqa: BLE001
        logger.debug("finalize_crashed_runs: partial reporter unavailable: %s", exc)
        return 0
    for crashed in detect_crashed_runs(output_dir):
        try:
            emit_partial_report(
                crashed.run_id,
                "auto_finalize_crashed",
                output_dir=output_dir,
            )
            written += 1
            logger.warning("auto-finalized crashed run %s", crashed.run_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("auto-finalize %s failed: %s", crashed.run_id, exc)
    return written


__all__ = [
    "CONTINUE_ON_NON_CRITICAL_ENV",
    "EMIT_PARTIAL_ENV",
    "MVR_ENABLED_ENV",
    "STRICT_CRITICAL_ENV",
    "StagePolicy",
    "abort_on_stage_failure",
    "bind_run",
    "continue_on_non_critical",
    "current_run",
    "emit_bound_partial_report",
    "emit_partial_on_shutdown",
    "finalize_crashed_runs",
    "mvr_enabled",
    "stage_policy_of",
    "strict_critical",
    "unbind_run",
]
