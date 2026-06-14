"""Analyzer performance ranking report.

Reads analyzer_duration_seconds histogram data and produces a ranked
table of slowest-to-fastest analyzers by P50, P95, and call count.

Usage:
    python scripts/analyzer_performance_report.py
    python scripts/analyzer_performance_report.py --json output.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _get_analyzer_stats() -> dict[str, dict]:
    """Collect per-analyzer timing stats from metrics."""
    from pathlib import Path

    from src.infrastructure.observability.metrics import get_metrics

    registry = get_metrics()

    # Load accumulated metrics from stability test runs (if any)
    analyzer_metrics_path = Path("output/stability_test/analyzer_metrics.json")
    if analyzer_metrics_path.exists():
        registry.load_from_file(analyzer_metrics_path)

    all_m = registry.get_all()

    # The analyzer_duration_seconds histogram tracks all analyzers globally
    # To get per-analyzer breakdown, we need to check if labels are used
    # or if we have separate metric instances per analyzer

    # For now, aggregate from the global histogram
    duration_hist = all_m.get("histograms", {}).get("cyber_pipeline_analyzer_duration_seconds", {})
    exec_count = all_m.get("counters", {}).get("cyber_pipeline_analyzer_execution_count", 0)
    fail_count = all_m.get("counters", {}).get("cyber_pipeline_analyzer_failure_count", 0)

    return {
        "duration_histogram": duration_hist,
        "total_executions": exec_count,
        "total_failures": fail_count,
    }


def _load_per_analyzer_timing() -> dict[str, list[dict]]:
    """Load per-analyzer timing from JSONL file, grouped by analyzer key."""
    from pathlib import Path

    timing_path = Path("output/stability_test/analyzer_timing.jsonl")
    if not timing_path.exists():
        return {}

    by_analyzer: dict[str, list[dict]] = {}
    for line in timing_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            key = record.get("analyzer", "unknown")
            by_analyzer.setdefault(key, []).append(record)
        except json.JSONDecodeError:
            continue

    return by_analyzer


def _print_per_analyzer_ranking(by_analyzer: dict[str, list[dict]]) -> None:
    """Print a ranked table of analyzers by P50 duration."""
    if not by_analyzer:
        print("  No per-analyzer timing data available.")
        print("  Run stability_test.py first to populate analyzer_timing.jsonl")
        return

    # Compute stats per analyzer
    rows = []
    for key, records in by_analyzer.items():
        durations = [r["elapsed_s"] for r in records]
        failures = sum(1 for r in records if r.get("status") == "error")
        durations.sort()
        n = len(durations)
        if n == 0:
            continue

        p50 = durations[int(n * 0.5)] if n > 1 else durations[0]
        p95 = durations[min(int(n * 0.95), n - 1)]
        total = sum(durations)

        rows.append(
            {
                "analyzer": key,
                "calls": n,
                "failures": failures,
                "p50_ms": p50 * 1000,
                "p95_ms": p95 * 1000,
                "total_s": total,
            }
        )

    # Sort by total time descending (most impactful first)
    rows.sort(key=lambda r: r["total_s"], reverse=True)

    print(f"  {'Analyzer':<40} {'Calls':>6} {'Fail':>5} {'P50':>8} {'P95':>8} {'Total':>8}")
    print("  " + "-" * 80)
    for row in rows:
        print(
            f"  {row['analyzer']:<40} {row['calls']:>6} {row['failures']:>5} "
            f"{row['p50_ms']:>7.1f}ms {row['p95_ms']:>7.1f}ms {row['total_s']:>7.2f}s"
        )

    # Top 5 slowest by P95
    by_p95 = sorted(rows, key=lambda r: r["p95_ms"], reverse=True)[:5]
    print("\n  Top 5 Slowest by P95:")
    print("  " + "-" * 60)
    for i, row in enumerate(by_p95, 1):
        print(
            f"  {i}. {row['analyzer']}: P95={row['p95_ms']:.1f}ms, calls={row['calls']}, total={row['total_s']:.2f}s"
        )


def _print_histogram_table(hist_data: dict) -> None:
    """Print a formatted histogram distribution table."""
    if not hist_data:
        print("  No histogram data available.")
        return

    buckets = hist_data.get("buckets", [])
    counts = hist_data.get("bucket_counts", [])
    total = hist_data.get("count", 0)
    sum_val = hist_data.get("sum", 0.0)

    if total == 0:
        print("  No observations recorded.")
        return

    avg = sum_val / total

    print(f"  Total observations: {total}")
    print(f"  Total duration:     {sum_val:.2f}s")
    print(f"  Average duration:   {avg * 1000:.1f}ms")
    print()

    # Estimate percentiles
    from src.infrastructure.observability.metrics import HistogramMetric

    # Create a temporary histogram to use percentile method
    hist = HistogramMetric(name="temp", description="")
    hist.buckets = tuple(buckets)
    hist.bucket_counts = list(counts)
    hist.sum_value = sum_val
    hist.count_value = total

    p50 = hist.percentile(50)
    p75 = hist.percentile(75)
    p90 = hist.percentile(90)
    p95 = hist.percentile(95)
    p99 = hist.percentile(99)

    print("  Percentile    Duration")
    print("  " + "-" * 30)
    print(f"  P50           {p50 * 1000:>8.1f}ms")
    print(f"  P75           {p75 * 1000:>8.1f}ms")
    print(f"  P90           {p90 * 1000:>8.1f}ms")
    print(f"  P95           {p95 * 1000:>8.1f}ms")
    print(f"  P99           {p99 * 1000:>8.1f}ms")
    print()

    # Bucket distribution
    print("  Bucket Distribution:")
    print("  " + "-" * 50)
    cumulative = 0
    for i, boundary in enumerate(buckets):
        count = counts[i] if i < len(counts) else 0
        cumulative += count
        pct = (count / total * 100) if total > 0 else 0
        (cumulative / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"  ≤{boundary:>6.3f}s  {count:>5} ({pct:>5.1f}%) {bar}")

    # Overflow bucket
    overflow = counts[-1] if counts else 0
    if overflow > 0:
        pct = overflow / total * 100
        bar = "█" * int(pct / 2)
        print(f"  >{buckets[-1]:>5.3f}s  {overflow:>5} ({pct:>5.1f}%) {bar}")


def _print_analyzer_benchmark() -> None:
    """Run a quick benchmark of all registered analyzers."""
    from src.analysis.plugin_runtime._bindings import ANALYZER_BINDINGS

    print(f"\n  Registered analyzers: {len(ANALYZER_BINDINGS)}")
    print()

    # List all registered analyzer keys
    print("  Analyzer Key                          Status")
    print("  " + "-" * 55)

    for key in sorted(ANALYZER_BINDINGS.keys()):
        binding = ANALYZER_BINDINGS[key]
        has_runner = binding.runner is not None
        status = "OK" if has_runner else "NO RUNNER"
        print(f"  {key:<38} {status}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyzer performance report")
    parser.add_argument("--json", type=str, help="Output JSON path")
    args = parser.parse_args()

    # Register metrics
    from src.infrastructure.observability.metrics import get_metrics, register_pipeline_metrics

    register_pipeline_metrics(get_metrics())

    print("=" * 72)
    print("  ANALYZER PERFORMANCE REPORT")
    print("=" * 72)
    print(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Get stats
    stats = _get_analyzer_stats()

    print("  Global Analyzer Metrics")
    print("  " + "=" * 50)
    print(f"  Total executions: {stats['total_executions']}")
    print(f"  Total failures:   {stats['total_failures']}")
    if stats["total_executions"] > 0:
        fail_rate = stats["total_failures"] / stats["total_executions"] * 100
        print(f"  Failure rate:     {fail_rate:.1f}%")
    print()

    # Duration histogram
    print("  Duration Distribution (analyzer_duration_seconds)")
    print("  " + "=" * 50)
    _print_histogram_table(stats["duration_histogram"])

    # Per-analyzer ranking
    by_analyzer = _load_per_analyzer_timing()
    print("  Per-Analyzer Ranking (by total time)")
    print("  " + "=" * 50)
    _print_per_analyzer_ranking(by_analyzer)

    # Analyzer registry
    _print_analyzer_benchmark()

    print("\n" + "=" * 72)
    print("  Per-analyzer timing data: output/stability_test/analyzer_timing.jsonl")
    print("  Run stability_test.py to accumulate timing across multiple scans.")
    print("=" * 72)

    # Save JSON
    if args.json:
        output = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stats": stats,
        }
        Path(args.json).write_text(json.dumps(output, indent=2))
        print(f"\n  Report saved to: {args.json}")


if __name__ == "__main__":
    main()
