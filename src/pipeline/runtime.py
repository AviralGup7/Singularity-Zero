"""Pipeline runtime entry point.

Provides the main() function that parses arguments, executes the pipeline,
and handles top-level errors gracefully.
"""

import argparse
import asyncio
import signal
import traceback
from pathlib import Path

from src.core.logging.pipeline_logging import emit_error, emit_warning
from src.pipeline.runner_support import parse_args
from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

shutdown_flag = False


def handle_signal(sig: int, frame: object = None) -> None:
    """Handle SIGINT/SIGTERM by setting the shutdown flag.

    Called when interrupt or termination signals are received.
    Sets a global flag to trigger graceful shutdown without
    abruptly terminating in-progress operations.

    Args:
        sig: Signal number (e.g., SIGINT=2, SIGTERM=15).
        frame: Current stack frame (unused, provided for signal handler signature).
    """
    global shutdown_flag
    shutdown_flag = True
    sig_name = f"Signal({sig})"
    try:
        sig_name = signal.Signals(sig).name
    except (ValueError, OSError):
        pass
    emit_warning(f"Received {sig_name}, shutting down gracefully...")


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

    return ok


def execute_pipeline(args: argparse.Namespace) -> int:
    """Execute the pipeline with the given parsed arguments.

    Args:
        args: Parsed argument namespace from argparse.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    return PipelineOrchestrator().run_sync(args)


async def _run_replay(args: argparse.Namespace) -> int:
    """Handle --replay: unpack artifact pack and run pipeline with verification."""
    import json
    import tempfile

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

    with tempfile.TemporaryDirectory() as tmp_output:
        with open(config_file) as f:
            config = json.load(f)
        with open(scope_file) as f:
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

        from src.dashboard.launcher_forensics import build_launcher_replay_manifest

        tmp_path = Path(tmp_output)
        launcher_dirs = list(tmp_path.glob("_launcher/*"))
        if not launcher_dirs:
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


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the pipeline runtime.

    Returns:
        Exit code (0 for success, 130 for interrupt, 1 for error).
    """
    try:
        args = parse_args(argv)
        if not _preflight_checks(args):
            return 1

        loop = asyncio.new_event_loop()
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, handle_signal, sig)
                except NotImplementedError:
                    signal.signal(sig, handle_signal)

            async def _run_with_shutdown_check() -> int:
                try:
                    return await PipelineOrchestrator().run(args)
                finally:
                    if shutdown_flag:
                        emit_warning("Shutdown flag detected, persisting partial results...")

            if getattr(args, "replay_archive", None):
                return loop.run_until_complete(_run_replay(args))

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
