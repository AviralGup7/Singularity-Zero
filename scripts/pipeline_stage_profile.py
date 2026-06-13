"""Pipeline stage profiling.

Runs a scan and records per-stage timing to identify bottlenecks.

Usage:
    python scripts/pipeline_stage_profile.py --target example.com
    python scripts/pipeline_stage_profile.py --config configs/config.json --scope scope.txt
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _get_stage_metrics() -> dict[str, dict]:
    """Collect stage timing metrics from the registry."""
    from src.infrastructure.observability.metrics import get_metrics

    registry = get_metrics()
    all_m = registry.get_all()

    stage_duration = all_m.get("histograms", {}).get("cyber_pipeline_stage_duration_seconds", {})
    stage_events = all_m.get("counters", {}).get("cyber_pipeline_pipeline_stage_events_total", 0)
    stage_failures = all_m.get("counters", {}).get("cyber_pipeline_stage_failure_count", 0)
    pipeline_runs = all_m.get("counters", {}).get("cyber_pipeline_pipeline_run_count", 0)
    pipeline_success = all_m.get("counters", {}).get("cyber_pipeline_pipeline_success_count", 0)

    return {
        "stage_duration": stage_duration,
        "stage_events": stage_events,
        "stage_failures": stage_failures,
        "pipeline_runs": pipeline_runs,
        "pipeline_success": pipeline_success,
    }


def _print_stage_profile(hist_data: dict) -> None:
    """Print stage timing profile from histogram data."""
    if not hist_data:
        print("  No stage duration data available.")
        return

    buckets = hist_data.get("buckets", [])
    counts = hist_data.get("bucket_counts", [])
    total = hist_data.get("count", 0)
    sum_val = hist_data.get("sum", 0.0)

    if total == 0:
        print("  No stage observations recorded.")
        return

    avg = sum_val / total

    from src.infrastructure.observability.metrics import HistogramMetric

    hist = HistogramMetric(name="temp", description="")
    hist.buckets = tuple(buckets)
    hist.bucket_counts = list(counts)
    hist.sum_value = sum_val
    hist.count_value = total

    p50 = hist.percentile(50)
    p90 = hist.percentile(90)
    p95 = hist.percentile(95)

    print(f"  Total stage completions: {total}")
    print(f"  Total duration:          {sum_val:.2f}s")
    print(f"  Average stage duration:  {avg * 1000:.1f}ms")
    print()

    print("  Percentile    Duration")
    print("  " + "-" * 30)
    print(f"  P50           {p50 * 1000:>8.1f}ms")
    print(f"  P90           {p90 * 1000:>8.1f}ms")
    print(f"  P95           {p95 * 1000:>8.1f}ms")
    print()

    # Bucket distribution
    print("  Duration Distribution:")
    print("  " + "-" * 55)
    cumulative = 0
    for i, boundary in enumerate(buckets):
        count = counts[i] if i < len(counts) else 0
        cumulative += count
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * max(1, int(pct / 2))
        print(f"  ≤{boundary:>6.3f}s  {count:>5} ({pct:>5.1f}%) {bar}")

    overflow = counts[-1] if counts else 0
    if overflow > 0:
        pct = overflow / total * 100
        bar = "█" * max(1, int(pct / 2))
        print(f"  >{buckets[-1]:>5.3f}s  {overflow:>5} ({pct:>5.1f}%) {bar}")


def _print_stage_list() -> None:
    """Print known pipeline stages with timeouts."""
    # Hardcoded to avoid deep import chain issues
    stages = {
        "subdomains": 600,
        "live_hosts": 900,
        "waf": 120,
        "urls": 900,
        "parameters": 120,
        "ranking": 60,
        "passive_scan": 300,
        "active_scan": 900,
        "semgrep": 600,
        "validation": 300,
        "intelligence": 180,
        "access_control": 600,
        "reporting": 300,
        "nuclei": 600,
        "git_diff_crawl": 30,
        "sarif_export": 30,
    }
    print("  Known Pipeline Stages:")
    print("  " + "-" * 55)
    print(f"  {'Stage':<25} {'Timeout':>10}")
    print("  " + "-" * 55)
    for stage, timeout in sorted(stages.items(), key=lambda x: x[1], reverse=True):
        print(f"  {stage:<25} {timeout:>7}s")


def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline stage profiler")
    parser.add_argument("--config", type=str, help="Path to config.json")
    parser.add_argument("--scope", type=str, help="Path to scope.txt")
    parser.add_argument("--target", type=str, help="Target domain (creates temp config/scope)")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode")
    parser.add_argument("--json", type=str, help="Output JSON path")
    args = parser.parse_args()

    # Register metrics
    from src.infrastructure.observability.metrics import get_metrics, register_pipeline_metrics

    register_pipeline_metrics(get_metrics())

    print("=" * 72)
    print("  PIPELINE STAGE PROFILER")
    print("=" * 72)
    print(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Show known stages
    _print_stage_list()
    print()

    # Run scan if target provided
    if args.target or args.config:
        if args.target:
            work_dir = Path("output/stage_profile")
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

        print("  Running scan...")
        print(f"  Config: {config_path}")
        print(f"  Scope:  {scope_path}")
        print()

        from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

        scan_args = argparse.Namespace(
            config=config_path,
            scope=scope_path,
            dry_run=args.dry_run,
            skip_crtsh=True,
            refresh_cache=False,
            force_fresh_run=True,
        )

        start_time = time.time()
        orchestrator = PipelineOrchestrator()
        exit_code = asyncio.run(orchestrator.run(scan_args))
        elapsed = time.time() - start_time

        print(f"\n  Scan completed (exit={exit_code}, {elapsed:.1f}s)")
        print()

    # Collect and display metrics
    metrics = _get_stage_metrics()

    print("  Stage Metrics Summary")
    print("  " + "=" * 50)
    print(f"  Pipeline runs:     {metrics['pipeline_runs']}")
    print(f"  Pipeline success:  {metrics['pipeline_success']}")
    print(f"  Stage events:      {metrics['stage_events']}")
    print(f"  Stage failures:    {metrics['stage_failures']}")
    print()

    print("  Stage Duration Profile")
    print("  " + "=" * 50)
    _print_stage_profile(metrics["stage_duration"])

    print("\n" + "=" * 72)

    # Save JSON
    if args.json:
        output = {
            "timestamp": datetime.now(UTC).isoformat(),
            "metrics": metrics,
        }
        Path(args.json).write_text(json.dumps(output, indent=2))
        print(f"\n  Report saved to: {args.json}")


if __name__ == "__main__":
    main()
