"""Replace print() with logger.info() in http_profiler.py."""
path = r"D:\cyber security test pipeline - Copy\src\core\utils\http_profiler.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

# Add logger if not present
if "import logging" not in content:
    content = content.replace(
        '"""HTTP request profiling utilities."""\n',
        '"""HTTP request profiling utilities."""\n\nimport logging\nlogger = logging.getLogger(__name__)\n',
    )

# Replace print calls with logger.info
old_new = [
    ('print("  No HTTP profiling data collected.")', 'logger.info("No HTTP profiling data collected.")'),
    ('print(f"  HTTP Profile ({summary.total_requests} requests)")', 'logger.info("HTTP Profile (%s requests)", summary.total_requests)'),
    ('print("  " + "-" * 50)', 'logger.info("  " + "-" * 50)'),
    ('print(f"  Total duration:  {summary.total_duration_ms:.1f}ms")', 'logger.info("  Total duration:  %.1fms", summary.total_duration_ms)'),
    ('print(f"  Avg duration:    {summary.avg_duration_ms:.1f}ms")', 'logger.info("  Avg duration:    %.1fms", summary.avg_duration_ms)'),
    ('print(f"  P50:             {summary.p50_duration_ms:.1f}ms")', 'logger.info("  P50:             %.1fms", summary.p50_duration_ms)'),
    ('print(f"  P95:             {summary.p95_duration_ms:.1f}ms")', 'logger.info("  P95:             %.1fms", summary.p95_duration_ms)'),
    ('print(f"  P99:             {summary.p99_duration_ms:.1f}ms")', 'logger.info("  P99:             %.1fms", summary.p99_duration_ms)'),
    ('print(f"  Max:             {summary.max_duration_ms:.1f}ms")', 'logger.info("  Max:             %.1fms", summary.max_duration_ms)'),
    ('print(f"  Errors:          {summary.error_count} ({summary.error_rate}%)")', 'logger.info("  Errors:          %s (%s%%)", summary.error_count, summary.error_rate)'),
    ('print(f"  Avg DNS:         {summary.avg_dns_ms:.1f}ms")', 'logger.info("  Avg DNS:         %.1fms", summary.avg_dns_ms)'),
    ('print(f"  Avg Connect:     {summary.avg_connect_ms:.1f}ms")', 'logger.info("  Avg Connect:     %.1fms", summary.avg_connect_ms)'),
    ('print(f"  Avg TTFB:        {summary.avg_ttfb_ms:.1f}ms")', 'logger.info("  Avg TTFB:        %.1fms", summary.avg_ttfb_ms)'),
    ('print("\n  Slowest requests:")', 'logger.info("  Slowest requests:")'),
    ('print(f"    {req[\'label\'][:50]:<50} {req[\'duration_ms\']:.1f}ms")', 'logger.info("    %s %.1fms", req["label"][:50], req["duration_ms"])'),
]

for old, new in old_new:
    content = content.replace(old, new)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Fixed http_profiler.py")
