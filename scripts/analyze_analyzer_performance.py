"""Analyzer Performance Analysis Report.

Reads analyzer_metrics.json and produces:
1. Rankings by runtime, findings, failure rate, invocation count
2. Value scores (findings / runtime)
3. Slow, low-value, unused analyzer identification
4. Top 20 optimization targets, highest-value, and removal candidates
5. Cost-vs-value table

Usage:
    python scripts/analyze_analyzer_performance.py
    python scripts/analyze_analyzer_performance.py --json report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def load_metrics(path: str = "output/stability_test/analyzer_metrics.json") -> dict:
    p = Path(path)
    if not p.exists():
        print(f"ERROR: {p} not found. Run generate_analyzer_metrics.py first.")
        sys.exit(1)
    return json.loads(p.read_text(encoding="utf-8"))


def fmt(n: float, width: int = 8) -> str:
    if n >= 1000:
        return f"{n:>8,.0f}"
    if n >= 100:
        return f"{n:>8.0f}"
    if n >= 10:
        return f"{n:>8.1f}"
    return f"{n:>8.2f}"


def print_header(title: str) -> None:
    print()
    print("=" * 120)
    print(f"  {title}")
    print("=" * 120)


def print_subheader(title: str) -> None:
    print()
    print(f"  --- {title} ---")


def print_ranking_table(
    rows: list[dict],
    columns: list[tuple[str, str, str]],
    title: str,
    limit: int = 20,
) -> None:
    """Print a ranked table."""
    print_header(title)
    header = f"  {'#':>3}  "
    for col_key, col_label, col_align in columns:
        header += f"{col_label:>12}  "
    header += "KEY"
    print(header)
    print("  " + "-" * 118)

    for i, row in enumerate(rows[:limit], 1):
        line = f"  {i:>3}  "
        for col_key, col_label, col_align in columns:
            val = row.get(col_key, 0)
            if isinstance(val, float):
                if abs(val) >= 1000:
                    line += f"{val:>11,.0f} "
                elif abs(val) >= 100:
                    line += f"{val:>11.0f} "
                else:
                    line += f"{val:>11.2f} "
            else:
                line += f"{str(val):>12} "
            line += " "
        line += row.get("key", "")
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyzer Performance Analysis")
    parser.add_argument("--json", type=str, help="Output JSON path")
    parser.add_argument(
        "--metrics", type=str, default="output/stability_test/analyzer_metrics.json"
    )
    args = parser.parse_args()

    data = load_metrics(args.metrics)
    summary = data["summary"]
    analyzers = data["analyzers"]

    # Separate active vs stub analyzers
    active = [a for a in analyzers if a["has_runner"] and not a["is_stub"]]
    stubs = [a for a in analyzers if a["is_stub"] or not a["has_runner"]]

    # =========================================================================
    # EXECUTIVE SUMMARY
    # =========================================================================
    print_header("ANALYZER PERFORMANCE ANALYSIS REPORT")
    print()
    print(f"  Generated from: {data['metadata']['generated_at']}")
    print(f"  Source:          {data['metadata']['source']}")
    print()
    print(f"  Total analyzers registered:  {summary['total_analyzers']}")
    print(f"  Active analyzers (w/ runner): {summary['active_analyzers']}")
    print(f"  Stub analyzers (no runner):   {summary['stub_analyzers']}")
    print()
    print(f"  Total invocations:            {summary['total_invocations']:,}")
    print(f"  Total findings:               {summary['total_findings']:,.1f}")
    print(f"  Total failures:               {summary['total_failures']:,}")
    print(
        f"  Total runtime:                {summary['total_runtime_s']:,.1f}s ({summary['total_runtime_s'] / 60:.1f}m)"
    )
    print(f"  Avg findings/second:          {summary['avg_findings_per_second']:.2f}")
    print(f"  Overall failure rate:         {summary['overall_failure_rate'] * 100:.1f}%")
    print()

    # Cost breakdown by input_kind
    cost_by_kind: dict[str, dict] = {}
    for a in active:
        kind = a["input_kind"]
        if kind not in cost_by_kind:
            cost_by_kind[kind] = {"count": 0, "runtime": 0.0, "findings": 0.0, "invocations": 0}
        cost_by_kind[kind]["count"] += 1
        cost_by_kind[kind]["runtime"] += a["total_runtime_s"]
        cost_by_kind[kind]["findings"] += a["findings"]
        cost_by_kind[kind]["invocations"] += a["invocations"]

    print_subheader("Cost Breakdown by Input Kind")
    print(f"  {'Input Kind':<35} {'Count':>6} {'Runtime':>10} {'Findings':>10} {'Invocations':>12}")
    print("  " + "-" * 85)
    for kind, info in sorted(cost_by_kind.items(), key=lambda x: -x[1]["runtime"]):
        pct = info["runtime"] / summary["total_runtime_s"] * 100
        print(
            f"  {kind:<35} {info['count']:>6} "
            f"{info['runtime']:>9,.1f}s ({pct:>4.1f}%) "
            f"{info['findings']:>10,.1f} {info['invocations']:>12,}"
        )

    # =========================================================================
    # RANKING 1: TOP 20 BY TOTAL RUNTIME (Slow analyzers consuming most time)
    # =========================================================================
    by_runtime = sorted(active, key=lambda a: -a["total_runtime_s"])
    print_ranking_table(
        by_runtime,
        [
            ("total_runtime_s", "Runtime(s)", ">"),
            ("invocations", "Invocations", ">"),
            ("runtime_per_call_s", "PerCall(ms)", ">"),
            ("failure_rate", "FailRate%", ">"),
        ],
        "TOP 20 ANALYZERS BY TOTAL RUNTIME (Optimization Priority)",
    )

    # =========================================================================
    # RANKING 2: TOP 20 BY FINDINGS
    # =========================================================================
    by_findings = sorted(active, key=lambda a: -a["findings"])
    print_ranking_table(
        by_findings,
        [
            ("findings", "Findings", ">"),
            ("invocations", "Invocations", ">"),
            ("findings_per_second", "Find/s", ">"),
            ("value_score", "ValueSc", ">"),
        ],
        "TOP 20 ANALYZERS BY FINDINGS (Highest Output)",
    )

    # =========================================================================
    # RANKING 3: TOP 20 BY FAILURE RATE
    # =========================================================================
    by_failure = sorted(
        [a for a in active if a["failures"] > 0],
        key=lambda a: -a["failure_rate"],
    )
    print_ranking_table(
        by_failure,
        [
            ("failure_rate", "FailRate%", ">"),
            ("failures", "Failures", ">"),
            ("invocations", "Invocations", ">"),
            ("input_kind", "InputKind", "<"),
        ],
        "TOP 20 ANALYZERS BY FAILURE RATE (Reliability Risk)",
    )

    # =========================================================================
    # RANKING 4: TOP 20 BY INVOCATION COUNT
    # =========================================================================
    by_invocations = sorted(active, key=lambda a: -a["invocations"])
    print_ranking_table(
        by_invocations,
        [
            ("invocations", "Invocations", ">"),
            ("total_runtime_s", "Runtime(s)", ">"),
            ("findings", "Findings", ">"),
            ("findings_per_second", "Find/s", ">"),
        ],
        "TOP 20 ANALYZERS BY INVOCATION COUNT (Most Called)",
    )

    # =========================================================================
    # VALUE SCORE RANKING: findings / runtime
    # =========================================================================
    by_value = sorted(
        [a for a in active if a["total_runtime_s"] > 0],
        key=lambda a: -a["value_score"],
    )

    print_subheader("Value Score = Findings / Runtime (Higher = Better ROI)")
    print_ranking_table(
        by_value,
        [
            ("value_score", "ValueScore", ">"),
            ("findings", "Findings", ">"),
            ("total_runtime_s", "Runtime(s)", ">"),
            ("invocations", "Invocations", ">"),
        ],
        "TOP 20 HIGHEST VALUE ANALYZERS (Best Findings-per-Second)",
    )

    # Bottom 20 value (lowest ROI - candidates for removal or lazy loading)
    low_value = [a for a in by_value if a["value_score"] > 0][-20:]
    low_value.reverse()
    print_ranking_table(
        low_value,
        [
            ("value_score", "ValueScore", ">"),
            ("findings", "Findings", ">"),
            ("total_runtime_s", "Runtime(s)", ">"),
            ("invocations", "Invocations", ">"),
        ],
        "TOP 20 LOWEST VALUE ANALYZERS (Worst Findings-per-Second)",
    )

    # =========================================================================
    # REMOVAL CANDIDATES: Stubs + Low-Value Active
    # =========================================================================
    # Stubs: registered but never produce findings
    stub_rows = sorted(stubs, key=lambda a: -a["invocations"])[:20]
    print_ranking_table(
        stub_rows,
        [
            ("invocations", "Invocations", ">"),
            ("total_runtime_s", "Runtime(s)", ">"),
            ("findings", "Findings", ">"),
            ("input_kind", "InputKind", "<"),
        ],
        "TOP 20 STUB/UNUSED ANALYZERS (Candidates for Removal)",
    )

    # Active analyzers with zero or near-zero findings per second
    zero_findings = sorted(
        [a for a in active if a["findings"] < 20 and a["total_runtime_s"] > 1.0],
        key=lambda a: -a["total_runtime_s"],
    )[:20]
    if zero_findings:
        print_ranking_table(
            zero_findings,
            [
                ("total_runtime_s", "Runtime(s)", ">"),
                ("findings", "Findings", ">"),
                ("value_score", "ValueSc", ">"),
                ("input_kind", "InputKind", "<"),
            ],
            "TOP 20 ACTIVE ANALYZERS WITH LOW FINDINGS (Removal/Lazy Load Candidates)",
        )

    # =========================================================================
    # SLOW ANALYZERS (per-call latency)
    # =========================================================================
    by_per_call = sorted(active, key=lambda a: -a["runtime_per_call_s"])
    print_ranking_table(
        by_per_call,
        [
            ("runtime_per_call_s", "PerCall(s)", ">"),
            ("total_runtime_s", "Total(s)", ">"),
            ("invocations", "Invocations", ">"),
            ("input_kind", "InputKind", "<"),
        ],
        "TOP 20 SLOWEST ANALYZERS (Per-Call Latency)",
    )

    # =========================================================================
    # COST-VS-VALUE TABLE (comprehensive)
    # =========================================================================
    print_header("COST-VS-VALUE TABLE (All Active Analyzers)")
    print()
    print(
        f"  {'Key':<45} {'Cost':>6} {'Runtime':>9} {'Findings':>9} {'Value':>7} {'Invoc':>6} {'Fail%':>5}"
    )
    print("  " + "-" * 105)
    for a in sorted(active, key=lambda a: -a["value_score"]):
        cost_char = (
            "H" if a["cost_relative"] >= 0.8 else ("M" if a["cost_relative"] >= 0.4 else "L")
        )
        fail_pct = f"{a['failure_rate'] * 100:.1f}%" if a["failure_rate"] > 0 else "0.0%"
        print(
            f"  {a['key']:<45} [{cost_char}] "
            f"{a['total_runtime_s']:>8.1f}s "
            f"{a['findings']:>9.1f} "
            f"{a['value_score']:>7.3f} "
            f"{a['invocations']:>6} "
            f"{fail_pct:>5}"
        )

    # =========================================================================
    # RECOMMENDATIONS
    # =========================================================================
    print_header("OPTIMIZATION RECOMMENDATIONS")

    # 1. Removal candidates
    print_subheader("1. REMOVAL CANDIDATES (90 stub analyzers)")
    print(f"  {len(stubs)} analyzers are registered with runner=None and produce zero findings.")
    print("  They consume memory in ANALYZER_BINDINGS dict but add no value.")
    print(f"  Impact: Reduces binding registry from {summary['total_analyzers']} to {len(active)}")
    print("  Priority: HIGH - reduces iteration overhead in run_analysis_plugins()")
    print()

    # 2. Lazy loading candidates
    lazy_candidates = sorted(
        [a for a in active if a["invocations"] < 150 and a["total_runtime_s"] < 50],
        key=lambda a: -a["total_runtime_s"],
    )[:15]
    print_subheader("2. LAZY LOADING CANDIDATES (Low-frequency active analyzers)")
    print(f"  {len(lazy_candidates)} active analyzers run infrequently (<150 invocations)")
    print("  and contribute <50s total runtime. Consider lazy-loading them.")
    for a in lazy_candidates:
        print(
            f"    - {a['key']:<45} invocations={a['invocations']:>4}  runtime={a['total_runtime_s']:.1f}s"
        )

    # 3. Batching candidates
    print_subheader("3. BATCHING CANDIDATES (High invocation count)")
    batch_candidates = sorted(active, key=lambda a: -a["invocations"])[:10]
    print(f"  These {len(batch_candidates)} analyzers have the highest invocation counts.")
    print("  Batching multiple URLs per call would reduce overhead.")
    for a in batch_candidates:
        batch_savings = a["invocations"] * 0.005  # 5ms overhead per call
        print(
            f"    - {a['key']:<45} invocations={a['invocations']:>4}  est_overhead={batch_savings:.1f}s"
        )

    # 4. Timeout tuning candidates
    timeout_candidates = sorted(
        [a for a in active if a["failure_rate"] > 0.05],
        key=lambda a: -a["failure_rate"],
    )[:10]
    print_subheader("4. TIMEOUT TUNING CANDIDATES (High failure rate)")
    print(f"  {len(timeout_candidates)} analyzers have >5% failure rate.")
    print("  Consider increasing timeouts or implementing retry logic.")
    for a in timeout_candidates:
        print(
            f"    - {a['key']:<45} failure_rate={a['failure_rate'] * 100:.1f}% "
            f"failures={a['failures']} input_kind={a['input_kind']}"
        )

    # 5. Slow analyzer mitigation
    print_subheader("5. SLOW ANALYZER MITIGATION (>2s per call)")
    slow_analyzers = sorted(
        [a for a in active if a["runtime_per_call_s"] > 2.0],
        key=lambda a: -a["runtime_per_call_s"],
    )
    for a in slow_analyzers:
        print(
            f"    - {a['key']:<45} per_call={a['runtime_per_call_s']:.2f}s "
            f"total={a['total_runtime_s']:.1f}s findings={a['findings']:.0f}"
        )

    # =========================================================================
    # SUMMARY TABLE
    # =========================================================================
    print_header("EXECUTIVE SUMMARY TABLE")
    print()
    print(f"  {'Category':<40} {'Count':>8} {'Runtime':>12} {'Findings':>12}")
    print("  " + "-" * 80)

    total_active_runtime = sum(a["total_runtime_s"] for a in active)
    total_active_findings = sum(a["findings"] for a in active)

    high_cost = [a for a in active if a["cost_relative"] >= 0.8]
    med_cost = [a for a in active if 0.4 <= a["cost_relative"] < 0.8]
    low_cost = [a for a in active if a["cost_relative"] < 0.4]

    print(
        f"  {'Active analyzers':<40} {len(active):>8} {total_active_runtime:>11,.1f}s {total_active_findings:>12,.1f}"
    )
    print(f"  {'Stub analyzers (no runner)':<40} {len(stubs):>8} {'0.0s':>12} {'0.0':>12}")
    print(f"  {'---':<40} {'---':>8} {'---':>12} {'---':>12}")
    print(
        f"  {'HIGH COST (active/cache)':<40} {len(high_cost):>8} {sum(a['total_runtime_s'] for a in high_cost):>11,.1f}s {sum(a['findings'] for a in high_cost):>12,.1f}"
    )
    print(
        f"  {'MEDIUM COST (local analysis)':<40} {len(med_cost):>8} {sum(a['total_runtime_s'] for a in med_cost):>11,.1f}s {sum(a['findings'] for a in med_cost):>12,.1f}"
    )
    print(
        f"  {'LOW COST (parsing/trivial)':<40} {len(low_cost):>8} {sum(a['total_runtime_s'] for a in low_cost):>11,.1f}s {sum(a['findings'] for a in low_cost):>12,.1f}"
    )
    print()

    # Savings estimate
    stub_memory = len(stubs) * 0.5  # ~0.5KB per binding entry
    print(
        f"  Potential runtime savings from removing stubs:  ~{stub_memory:.0f}KB memory + 0s runtime"
    )
    print(
        f"  Potential runtime savings from lazy loading:   ~{sum(a['total_runtime_s'] for a in lazy_candidates):.1f}s"
    )
    print(
        f"  Potential runtime savings from batching:       ~{sum(a['invocations'] * 0.005 for a in batch_candidates):.1f}s overhead"
    )
    print()

    print("=" * 120)
    print("  END OF ANALYZER PERFORMANCE ANALYSIS REPORT")
    print("=" * 120)

    # Save JSON report
    if args.json:
        report = {
            "metadata": data["metadata"],
            "summary": summary,
            "rankings": {
                "by_runtime": [a["key"] for a in by_runtime[:20]],
                "by_findings": [a["key"] for a in by_findings[:20]],
                "by_failure_rate": [a["key"] for a in by_failure[:20]],
                "by_invocations": [a["key"] for a in by_invocations[:20]],
                "highest_value": [a["key"] for a in by_value[:20]],
                "lowest_value": [a["key"] for a in low_value[:20]],
                "removal_candidates": [a["key"] for a in stubs[:20]],
                "slowest": [a["key"] for a in by_per_call[:20]],
            },
            "recommendations": {
                "removal_count": len(stubs),
                "lazy_load_candidates": [a["key"] for a in lazy_candidates],
                "batch_candidates": [a["key"] for a in batch_candidates],
                "timeout_tuning": [a["key"] for a in timeout_candidates],
            },
        }
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n  JSON report saved to: {args.json}")


if __name__ == "__main__":
    main()
