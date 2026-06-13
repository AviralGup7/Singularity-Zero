"""Long-running stability test.

Runs N scans and records memory, thread, task, and queue metrics
at intervals to detect leaks and instability.

Usage:
    python scripts/stability_test.py --target example.com --scans 100
    python scripts/stability_test.py --config configs/config.json --scope scope.txt --scans 500
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _snapshot_metrics() -> dict[str, float]:
    """Collect a point-in-time snapshot of system metrics."""
    try:
        import psutil

        proc = psutil.Process(os.getpid())
        mem = proc.memory_info().rss / (1024 * 1024)
        threads = proc.num_threads()
    except ImportError:
        mem = 0.0
        threads = 0

    import asyncio

    try:
        loop = asyncio.get_running_loop()
        tasks = len(asyncio.all_tasks(loop)) if loop.is_running() else 0
    except RuntimeError:
        tasks = 0

    return {
        "rss_mb": round(mem, 2),
        "thread_count": threads,
        "asyncio_tasks": tasks,
        "timestamp": time.time(),
    }


def _snapshot_analyzer_metrics() -> dict[str, dict[str, float]]:
    """Get analyzer timing stats from the metrics registry."""
    from src.infrastructure.observability.metrics import get_metrics

    registry = get_metrics()
    all_m = registry.get_all()

    duration_hist = all_m.get("histograms", {}).get("cyber_pipeline_analyzer_duration_seconds", {})
    count_counter = all_m.get("counters", {}).get("cyber_pipeline_analyzer_execution_count", 0)
    failure_counter = all_m.get("counters", {}).get("cyber_pipeline_analyzer_failure_count", 0)

    return {
        "duration": duration_hist,
        "execution_count": count_counter,
        "failure_count": failure_counter,
    }


def _cleanup_run_lock(target_name: str) -> None:
    """Release the distributed run lock for a target after scan completes."""
    from pathlib import Path

    # Lock files are stored in ~/.cache/pipeline/run_lock/
    lock_dir = Path.home() / ".cache" / "pipeline" / "run_lock"
    lock_file = lock_dir / f"{target_name}.lock"
    try:
        if lock_file.exists():
            lock_file.unlink()
    except Exception:
        pass


def _run_scan(args: argparse.Namespace, config_path: str, scope_path: str) -> int:
    """Run a single scan and return exit code."""
    import asyncio

    from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

    scan_args = argparse.Namespace(
        config=config_path,
        scope=scope_path,
        dry_run=args.dry_run,
        skip_crtsh=True,
        refresh_cache=False,
        force_fresh_run=True,
    )

    # Extract target name from config to clean up lock later
    import json

    with open(config_path) as f:
        config = json.load(f)
    target_name = config.get("target_name", "unknown")

    orchestrator = PipelineOrchestrator()
    exit_code = asyncio.run(orchestrator.run(scan_args))

    # Release lock so next scan can proceed
    _cleanup_run_lock(target_name)

    return exit_code


def _print_report(snapshots: list[dict], scan_count: int, elapsed: float) -> None:
    """Print stability report from collected snapshots."""
    print("\n" + "=" * 72)
    print("  STABILITY TEST REPORT")
    print("=" * 72)
    print(f"  Total scans: {scan_count}")
    print(f"  Total time:  {elapsed:.1f}s ({elapsed / 60:.1f}m)")
    print(f"  Snapshots:   {len(snapshots)}")
    print()

    if not snapshots:
        print("  No snapshots collected.")
        return

    rss_values = [s["rss_mb"] for s in snapshots if s["rss_mb"] > 0]
    thread_values = [s["thread_count"] for s in snapshots if s["thread_count"] > 0]
    task_values = [s["asyncio_tasks"] for s in snapshots]

    print("  Metric               Start       End         Delta     Status")
    print("  " + "-" * 66)

    def _print_row(name: str, values: list[float], unit: str = "") -> None:
        if not values:
            print(f"  {name:<20} {'N/A':>10}  {'N/A':>10}  {'N/A':>10}  N/A")
            return
        start = values[0]
        end = values[-1]
        delta = end - start
        max(values)
        # Heuristic: if delta > 20% of start and start > 0, flag as potential leak
        if start > 0 and delta > start * 0.2 and delta > 10:
            status = "WARN GROWING"
        elif start > 0 and abs(delta) < start * 0.05:
            status = "STABLE"
        else:
            status = "OK"
        print(
            f"  {name:<20} {start:>8.1f}{unit}  {end:>8.1f}{unit}  {delta:>+8.1f}{unit}  {status}"
        )

    _print_row("RSS Memory", rss_values, " MB")
    _print_row("Thread Count", thread_values)
    _print_row("Asyncio Tasks", task_values)

    # Peak memory
    if rss_values:
        print(f"\n  Peak RSS: {max(rss_values):.1f} MB")
        print(f"  Min RSS:  {min(rss_values):.1f} MB")
        print(f"  Avg RSS:  {sum(rss_values) / len(rss_values):.1f} MB")

    # Tracemalloc peak
    if tracemalloc.is_tracing():
        current, peak = tracemalloc.get_traced_memory()
        print(f"\n  Python Heap Peak: {peak / 1024 / 1024:.1f} MB")
        print(f"  Python Heap Current: {current / 1024 / 1024:.1f} MB")

    print("\n" + "=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline stability test")
    parser.add_argument("--config", type=str, help="Path to config.json")
    parser.add_argument("--scope", type=str, help="Path to scope.txt")
    parser.add_argument("--target", type=str, help="Target domain (creates temp config/scope)")
    parser.add_argument("--scans", type=int, default=10, help="Number of scans to run")
    parser.add_argument("--interval", type=int, default=1, help="Snapshots between scans")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode")
    parser.add_argument("--output", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    if not args.config and not args.target:
        parser.error("Either --config/--scope or --target is required")

    # Prepare config/scope files
    if args.target:
        work_dir = Path("output/stability_test")
        work_dir.mkdir(parents=True, exist_ok=True)

        config_path = str(work_dir / "config.json")
        config = {
            "target_name": args.target,
            "output_dir": str(work_dir / "output"),
            "tools": {},
            "mode": "quick",
            "analysis": {"max_iteration_limit": 1, "finding_feedback_limit": 5},
        }
        with open(config_path, "w") as f:
            json.dump(config, f)

        scope_path = str(work_dir / "scope.txt")
        with open(scope_path, "w") as f:
            f.write(f"{args.target}\n")
    else:
        config_path = args.config
        scope_path = args.scope

    print("=" * 72)
    print("  STABILITY TEST")
    print("=" * 72)
    print(f"  Config: {config_path}")
    print(f"  Scope:  {scope_path}")
    print(f"  Scans:  {args.scans}")
    print(f"  Mode:   {'dry-run' if args.dry_run else 'live'}")
    print("=" * 72)

    # Start tracing
    tracemalloc.start()

    # Register metrics
    from src.infrastructure.observability.metrics import get_metrics, register_pipeline_metrics

    register_pipeline_metrics(get_metrics())

    snapshots: list[dict] = []
    results: list[dict] = []
    start_time = time.time()

    # Initial snapshot
    snap = _snapshot_metrics()
    snap["scan"] = 0
    snapshots.append(snap)

    for i in range(1, args.scans + 1):
        scan_start = time.time()
        print(f"\n[{i}/{args.scans}] Running scan...", end=" ", flush=True)

        try:
            exit_code = _run_scan(args, config_path, scope_path)
            scan_duration = time.time() - scan_start
            print(f"done (exit={exit_code}, {scan_duration:.1f}s)")

            results.append(
                {
                    "scan": i,
                    "exit_code": exit_code,
                    "duration_s": round(scan_duration, 2),
                }
            )
        except Exception as exc:
            scan_duration = time.time() - scan_start
            print(f"FAILED ({scan_duration:.1f}s): {exc}")
            results.append(
                {
                    "scan": i,
                    "exit_code": -1,
                    "duration_s": round(scan_duration, 2),
                    "error": str(exc),
                }
            )

        # Snapshot at intervals
        if i % args.interval == 0 or i == args.scans:
            snap = _snapshot_metrics()
            snap["scan"] = i
            snapshots.append(snap)

    elapsed = time.time() - start_time

    # Print report
    _print_report(snapshots, args.scans, elapsed)

    # Print scan results summary
    successes = sum(1 for r in results if r["exit_code"] == 0)
    failures = sum(1 for r in results if r["exit_code"] != 0)
    avg_duration = sum(r["duration_s"] for r in results) / max(1, len(results))

    print(f"\n  Scans: {successes} succeeded, {failures} failed")
    print(f"  Avg scan duration: {avg_duration:.1f}s")
    print("=" * 72)

    # Save output
    output_path = args.output or f"output/stability_test/report_{int(time.time())}.json"
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "total_scans": args.scans,
        "elapsed_seconds": round(elapsed, 2),
        "snapshots": snapshots,
        "results": results,
        "summary": {
            "successes": successes,
            "failures": failures,
            "avg_duration_s": round(avg_duration, 2),
        },
    }
    output_file.write_text(json.dumps(report, indent=2))
    print(f"\n  Report saved to: {output_path}")


if __name__ == "__main__":
    main()
