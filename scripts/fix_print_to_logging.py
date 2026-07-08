"""Replace debug print() calls with logger.*() calls in non-CLI files."""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"

def fix_bin_downloader():
    fp = SRC / "core" / "utils" / "bin_downloader.py"
    content = fp.read_text(encoding="utf-8")
    
    # Lines that have a print() mirroring a logger call just before
    # Line 143: print(f"\n[*] {message}") -> already has logger.info(message) at 141
    content = content.replace(
        '            print(f"\\n[*] {message}")\n',
        '            logger.info(message)\n',
    )
    # Line 164: print("  └─ Downloading from GitHub...")
    content = content.replace(
        '                print("  └─ Downloading from GitHub...")\n',
        '                logger.info("Downloading from GitHub...")\n',
    )
    # Line 206: print("  └─ Unpacking archive and resolving binary...")
    content = content.replace(
        '                print("  └─ Unpacking archive and resolving binary...")\n',
        '                logger.info("Unpacking archive and resolving binary...")\n',
    )
    # Line 262: print(f"  └─ [✓] {success_msg}")
    content = content.replace(
        '                print(f"  └─ [\u2713] {success_msg}")\n',
        '                logger.info(success_msg)\n',
    )
    # Line 270: print(f"  └─ [✗] Error: {exc}")
    content = content.replace(
        '                print(f"  └─ [\u2717] Error: {exc}")\n',
        '                logger.error("Error: %s", exc)\n',
    )
    fp.write_text(content, encoding="utf-8")
    print(f"Fixed: {fp}")

def fix_runtime():
    fp = SRC / "pipeline" / "runtime.py"
    content = fp.read_text(encoding="utf-8")
    # Line 192: print(format_validation_report(report))
    content = content.replace(
        '    print(format_validation_report(report))\n',
        '    logger.info(format_validation_report(report))\n',
    )
    fp.write_text(content, encoding="utf-8")
    print(f"Fixed: {fp}")

def fix_http_profiler():
    fp = SRC / "core" / "utils" / "http_profiler.py"
    content = fp.read_text(encoding="utf-8")
    
    # Add logging import
    if "import logging" not in content:
        content = content.replace(
            '"""HTTP request profiling utilities."""\n',
            '"""HTTP request profiling utilities."""\n\nimport logging\nlogger = logging.getLogger(__name__)\n',
        )
    
    # Replace all print() calls with logger.info()
    replacements = [
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
        ('print("\\n  Slowest requests:")', 'logger.info("  Slowest requests:")'),
        ('print(f"    {req[\'label\'][:50]:<50} {req[\'duration_ms\']:.1f}ms")', 'logger.info("    %s %s", req["label"][:50], f\'{req["duration_ms"]:.1f}ms\')'),
    ]
    
    for old, new in replacements:
        content = content.replace(old, new)
    
    fp.write_text(content, encoding="utf-8")
    print(f"Fixed: {fp}")

def fix_job_artifact_packager():
    fp = SRC / "pipeline" / "services" / "job_artifact_packager.py"
    content = fp.read_text(encoding="utf-8")
    # Lines 394-398: success output prints -> replace with logger.info
    content = content.replace(
        '        print(f"Archived to: {archive_path}")\n',
        '        logger.info("Archived to: %s", archive_path)\n',
    )
    content = content.replace(
        '        print(f"Size: {archive_path.stat().st_size:,} bytes")\n',
        '        logger.info("Size: %s bytes", f"{archive_path.stat().st_size:,}")\n',
    )
    content = content.replace(
        '        print(f"Verified unpack: job_id={snapshot.job_id} git={snapshot.git_commit_hash}")\n',
        '        logger.info("Verified unpack: job_id=%s git=%s", snapshot.job_id, snapshot.git_commit_hash)\n',
    )
    fp.write_text(content, encoding="utf-8")
    print(f"Fixed: {fp}")

if __name__ == "__main__":
    fix_bin_downloader()
    fix_runtime()
    fix_http_profiler()
    fix_job_artifact_packager()
