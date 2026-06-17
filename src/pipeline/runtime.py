"""Pipeline runtime entry point.

Provides the main() function that parses arguments, executes the pipeline,
and handles top-level errors gracefully.
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import signal
import stat
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

from src.core.logging.pipeline_logging import emit_error, emit_warning

logger = logging.getLogger(__name__)
from src.core.security.secret_validator import validate_or_raise
from src.pipeline.runner_support import parse_args
from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

# ``asyncio.Event`` works in both sync and async contexts. The previous
# implementation used a plain boolean which is racy when the SIGINT
# handler runs concurrently with the async pipeline (the handler set the
# flag, but the running coroutine never saw it).
_shutdown_events: dict[asyncio.AbstractEventLoop, asyncio.Event] = {}
_shutdown_event: asyncio.Event | None = None


def _shutdown_event_singleton() -> asyncio.Event:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

    if loop is None:
        global _shutdown_event
        if _shutdown_event is None:
            _shutdown_event = asyncio.Event()
        return _shutdown_event

    if loop not in _shutdown_events:
        _shutdown_events[loop] = asyncio.Event()
    return _shutdown_events[loop]


def _is_shutdown_requested() -> bool:
    return _shutdown_event_singleton().is_set()


def request_shutdown() -> None:
    """Public hook for in-process callers to trigger a graceful shutdown."""
    event = _shutdown_event_singleton()
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(event.set)
    else:
        event.set()

    # Also set global process fallback and all registered loop events to be safe
    global _shutdown_event
    if _shutdown_event is not None:
        _shutdown_event.set()
    for evt in _shutdown_events.values():
        try:
            evt.set()
        except Exception:  # noqa: S110
            pass


# Backwards-compatible alias used by tests / external callers that
# reference ``runtime.shutdown_flag``. ``shutdown_flag`` was a plain
# ``bool``; the new value is an ``asyncio.Event`` which is falsy when
# not set, so ``if not runtime.shutdown_flag:`` still reads naturally.
# NOTE: This is a lazy property to avoid creating an asyncio.Event at
# import time (which can fail in environments where no event loop
# exists at import time — Python 3.10+ changed default policy).


class _ShutdownFlagProxy:
    """Lazy proxy that creates the Event only when first accessed."""

    def __bool__(self) -> bool:
        return _shutdown_event_singleton().is_set()

    def is_set(self) -> bool:
        return _shutdown_event_singleton().is_set()

    def set(self) -> None:
        _shutdown_event_singleton().set()

    def clear(self) -> None:
        _shutdown_event_singleton().clear()

    def __await__(self) -> Any:
        return _shutdown_event_singleton().wait().__await__()


shutdown_flag = _ShutdownFlagProxy()


def handle_signal(sig: int, frame: object = None) -> None:
    """Handle SIGINT/SIGTERM by setting the shutdown flag.

    Called when interrupt or termination signals are received.
    Sets a global flag to trigger graceful shutdown without
    abruptly terminating in-progress operations.

    Args:
        sig: Signal number (e.g., SIGINT=2, SIGTERM=15).
        frame: Current stack frame (unused, provided for signal handler signature).
    """
    request_shutdown()
    sig_name = f"Signal({sig})"
    try:
        sig_name = signal.Signals(sig).name
    except (ValueError, OSError):
        pass
    emit_warning(f"Received {sig_name}, shutting down gracefully...")


def _make_secure_tempdir(prefix: str = "cyber-replay-") -> str:
    """Create a temporary directory with owner-only permissions.

    The previous implementation called ``tempfile.mkdtemp()`` with the
    default mode 0o707, which is world-readable/executable on POSIX.
    Replay artifacts may include extracted configuration and PII, so we
    tighten the permissions immediately after creation.
    """
    path = tempfile.mkdtemp(prefix=prefix)
    try:
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        # Windows may not support chmod on temp dirs; ACLs already
        # restrict to the current user.
        pass
    return path


def _preflight_checks(args: argparse.Namespace) -> bool:
    """Validate prerequisites before starting the pipeline.

    Args:
        args: Parsed argument namespace from argparse.

    Returns:
        True if all checks pass, False otherwise.
    """
    config_path = Path(args.config).resolve()
    scope_path = Path(args.scope).resolve()

    ok = True

    if not config_path.is_file():
        emit_error(f"Configuration file not found: {config_path}")
        ok = False

    if not scope_path.is_file():
        emit_error(f"Scope file not found: {scope_path}")
        ok = False

    if not ok:
        return False

    try:
        from src.core.config import load_config
        from src.pipeline.validation import format_validation_report, validate_config

        config = load_config(config_path)
        resume_from = getattr(args, "resume_from", None)
        if resume_from:
            if not hasattr(config, "_resume_from"):
                config._resume_from = resume_from
        with open(scope_path, encoding="utf-8") as f:
            scope_entries = [line.strip() for line in f if line.strip()]

        all_ok, report = validate_config(config.to_dict(), scope_entries, str(config.output_dir))
        if not all_ok:
            emit_error("Pre-flight configuration validation failed:")
            print(format_validation_report(report))
            return False
    except Exception as exc:
        emit_error(f"Pre-flight configuration parsing/validation failed: {exc}")
        return False

    return True


def execute_pipeline(args: argparse.Namespace) -> int:
    """Execute the pipeline with the given parsed arguments.

    Args:
        args: Parsed argument namespace from argparse.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    return PipelineOrchestrator().run_sync(args)


async def _run_continuous(args: argparse.Namespace) -> int:
    """Run continuous monitoring mode."""
    import os

    from src.core.checkpoint import create_checkpoint_manager, generate_run_id
    from src.core.monitoring.asset_inventory import AssetInventoryManager
    from src.core.monitoring.continuous_scan import ContinuousScanMode
    from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

    config_path = Path(args.config).resolve()
    from src.core.config import load_config

    config = load_config(config_path)
    output_dir = Path(config.output_dir)
    target_name = str(getattr(config, "target_name", "continuous") or "continuous")

    continuous_run_id = generate_run_id()
    checkpoint_mgr = create_checkpoint_manager(
        output_dir,
        target_name,
        run_id=continuous_run_id,
        storage_config=getattr(config, "storage", None),
    )

    inventory_config: dict[str, Any] = {
        "cloud_providers": os.getenv("CLOUD_PROVIDERS", ""),
        "aws_region": os.getenv("AWS_REGION", ""),
        "gcp_project": os.getenv("GCP_PROJECT", ""),
        "azure_subscription": os.getenv("AZURE_SUBSCRIPTION_ID", ""),
    }
    inventory_mgr = AssetInventoryManager(inventory_config)

    continuous_mode = ContinuousScanMode(
        orchestrator=PipelineOrchestrator(),
        inventory_mgr=inventory_mgr,
        checkpoint_mgr=checkpoint_mgr,
    )

    interval = int(getattr(args, "monitor_interval", 3600) or 3600)
    asset_diff_only = bool(getattr(args, "asset_diff_only", False))

    try:
        await continuous_mode.run_continuous(
            interval_seconds=interval,
            output_dir=output_dir,
            target_name=target_name,
            asset_diff_only=asset_diff_only,
            config_path=config_path,
        )
    except asyncio.CancelledError:
        pass
    return 0


async def _run_replay(args: argparse.Namespace) -> int:
    """Handle --replay: unpack artifact pack and run pipeline with verification."""
    from src.core.logging.pipeline_logging import emit_info, emit_warning
    from src.pipeline.services.job_artifact_packager import JobArtifactPackager
    from src.pipeline.services.pipeline_flow import run_pipeline

    archive_path = Path(args.replay_archive).resolve()
    if not archive_path.exists():
        emit_error(f"Replay archive not found: {archive_path}")
        return 1

    emit_info(f"Unpacking replay archive: {archive_path}")
    packager = JobArtifactPackager(archive_path.parent)
    try:
        snapshot, extract_dir = packager.unpackage_snapshot(archive_path)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        emit_error(f"Failed to unpack archive: {exc}")
        return 1

    config_file = extract_dir / "artifacts" / "config.json"
    scope_file = extract_dir / "artifacts" / "scope.txt"

    if not config_file.exists() or not scope_file.exists():
        emit_error("Invalid archive: missing config.json or scope.txt")
        return 1

    emit_info(
        f"Replaying job {snapshot.job_id}: "
        f"target={snapshot.config_json.get('target_name', '?')} "
        f"git={snapshot.git_commit_hash}"
    )

    tmp_output = _make_secure_tempdir()
    try:
        with open(config_file, encoding="utf-8") as f:
            config = json.load(f)
        with open(scope_file, encoding="utf-8") as f:
            scope_entries = [line.strip() for line in f if line.strip()]

        replay_args = argparse.Namespace(
            config=str(config_file),
            scope=str(scope_file),
            refresh_cache=False,
            force_fresh_run=True,
            skip_crtsh=False,
            dry_run=False,
            replay_archive=None,
        )
        setattr(replay_args, "_loaded_config", config)
        setattr(replay_args, "_loaded_scope_entries", scope_entries)

        run_pipeline(config, scope_entries, tmp_output, replay_args)

        from src.core.contracts.protocol_registry import get_launcher_manifest

        launcher_manifest = get_launcher_manifest()
        if launcher_manifest is None:
            emit_warning("Launcher manifest not available")
            return 1
        build_launcher_replay_manifest = launcher_manifest.build_launcher_replay_manifest

        tmp_path = Path(tmp_output)
        launcher_dirs = list(tmp_path.glob("_launcher/*"))
        if not launcher_dirs:
            is_reporting_skipped = (
                config.get("dry_run", False)
                or (isinstance(config.get("stages"), list) and "reporting" not in config["stages"])
                or (
                    isinstance(config.get("skip_stages"), list)
                    and "reporting" in config["skip_stages"]
                )
            )
            if is_reporting_skipped:
                emit_info(
                    "No launcher artifacts expected (dry-run or reporting skipped). Replay successful."
                )
                return 0
            emit_warning("No launcher artifacts produced during replay")
            return 1

        new_job_id = launcher_dirs[0].name
        new_manifest = build_launcher_replay_manifest(tmp_path, new_job_id)
        parity = packager.verify_parity(snapshot, new_manifest)

        mismatched = parity.get("changed_fields", [])
        warning_delta = parity.get("warning_count_delta", 0)
        status_changed = parity.get("status_changed", False)

        emit_info(
            f"Replay parity: status_changed={status_changed} "
            f"warning_delta={warning_delta} mismatched_fields={mismatched}"
        )

        if mismatched or status_changed:
            emit_warning(
                f"Parity mismatch: changed_fields={mismatched}, status_changed={status_changed}"
            )
            return 1

        emit_info("Replay parity: PASS")
        return 0
    finally:
        shutil.rmtree(tmp_output, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the pipeline runtime.

    Returns:
        Exit code (0 for success, 130 for interrupt, 1 for error).
    """
    try:
        # Register plugin hooks from analysis and detection layers
        try:
            import src.analysis.plugin_registration  # noqa: F401
        except ImportError:
            pass
        try:
            import src.detection.cache_registration  # noqa: F401
        except ImportError:
            pass

        # Security: refuse to start the pipeline with placeholder secrets
        # in any non-development environment. The validator logs warnings
        # in dev and raises in production / CI.
        validate_or_raise()

        # Security: enforce production security requirements
        # (DASHBOARD_AUTH_DISABLED, default secrets, etc.)
        from src.core.security.secret_validator import enforce_production_security

        enforce_production_security()
        args = parse_args(argv)
        resume_from = getattr(args, "resume_from", None)
        if resume_from:
            if hasattr(args, "_loaded_config"):
                args._loaded_config._resume_from = resume_from
            else:
                args._resume_from = resume_from
        if getattr(args, "validate_config", False):
            from src.core.config import load_config
            from src.pipeline.validation import format_validation_report, validate_config

            config = load_config(Path(args.config).resolve())
            with open(args.scope, encoding="utf-8") as f:
                scope_entries = [line.strip() for line in f if line.strip()]
            all_ok, report = validate_config(
                config.to_dict(), scope_entries, str(config.output_dir)
            )
            print(format_validation_report(report))
            return 0 if all_ok else 1

        if not _preflight_checks(args):
            if not getattr(args, "continuous", False):
                return 1

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            _ = _shutdown_event_singleton()
            global shutdown_flag
            shutdown_flag = _ShutdownFlagProxy()

            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, handle_signal, sig)
                except NotImplementedError:
                    signal.signal(sig, handle_signal)

            _pipeline_started_at = time.time()

            if getattr(args, "continuous", False):
                return loop.run_until_complete(_run_continuous(args))

            async def _run_with_shutdown_check() -> int:
                from src.pipeline.runner_support import check_max_duration

                if check_max_duration(args, _pipeline_started_at):
                    emit_warning("Max-duration budget exhausted before stage execution.")
                    return 4
                try:
                    return await PipelineOrchestrator().run(args)
                finally:
                    # ``shutdown_flag`` is an ``asyncio.Event``; check
                    # ``is_set()`` to avoid the always-truthy trap.
                    if bool(getattr(shutdown_flag, "is_set", lambda: False)()):
                        emit_warning("Shutdown flag detected, persisting partial results...")

            if getattr(args, "replay_archive", None):
                return loop.run_until_complete(_run_replay(args))

            replay_stage = getattr(args, "replay_stage", None)
            replay_run_id = getattr(args, "replay_run_id", None)
            replay_traces = getattr(args, "replay_traces_run_id", None)
            if replay_stage and replay_run_id:
                from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

                logger.info("Replaying stage %s from run %s", replay_stage, replay_run_id)
                orchestrator = PipelineOrchestrator()
                outcome = loop.run_until_complete(
                    orchestrator._replay_single_stage(
                        replay_run_id,
                        replay_stage,
                        trace_dir=getattr(args, "trace_dir", ".ai/traces"),
                    )
                )
                return 0 if outcome is not None else 1
            if replay_traces:
                from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

                logger.info("Replaying all traced stages from run %s", replay_traces)
                orchestrator = PipelineOrchestrator()
                outcomes = loop.run_until_complete(
                    orchestrator._replay_traces(
                        replay_traces,
                        trace_dir=getattr(args, "trace_dir", ".ai/traces"),
                    )
                )
                return 0 if outcomes else 1

            return loop.run_until_complete(_run_with_shutdown_check())
        finally:
            loop.close()
    except KeyboardInterrupt:
        emit_warning("Interrupted by user.")
        return 130
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        emit_error(f"Pipeline failed: {exc}")
        emit_error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
