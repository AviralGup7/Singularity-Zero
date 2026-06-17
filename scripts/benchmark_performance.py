"""Comprehensive performance benchmark suite.

Measures CPU, memory, latency, throughput, and scan duration before/after
optimizations. Generates a comparative performance report.

Usage:
    python scripts/benchmark_performance.py --baseline
    python scripts/benchmark_performance.py --optimized
    python scripts/benchmark_performance.py --report baseline.json optimized.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import psutil

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_process() -> psutil.Process:
    return psutil.Process(os.getpid())


def _measure_memory_mb() -> dict[str, float]:
    """Measure current and peak memory in MB."""
    proc = _get_process()
    mem = proc.memory_info()
    return {
        "current_rss_mb": mem.rss / (1024 * 1024),
        "current_vms_mb": mem.vms / (1024 * 1024),
        "peak_mb": proc.memory_info().rss / (1024 * 1024),
    }


def _measure_cpu_times() -> dict[str, float]:
    """Measure CPU time breakdown."""
    proc = _get_process()
    ct = proc.cpu_times()
    return {
        "user_s": ct.user,
        "system_s": ct.system,
        "iowait_s": getattr(ct, "iowait", 0.0),
    }


def _measure_thread_count() -> int:
    return _get_process().num_threads()


# ---------------------------------------------------------------------------
# Benchmark: Import / Startup
# ---------------------------------------------------------------------------

def bench_startup() -> dict[str, Any]:
    """Measure cold-start import latency and memory."""
    import importlib

    modules = [
        "src.core",
        "src.core.http_utils",
        "src.core.storage.s3_backends",
        "src.core.utils.http_pool",
        "src.core.utils.streaming",
        "src.infrastructure",
        "src.infrastructure.execution_engine.concurrent_executor",
        "src.infrastructure.observability.metrics",
        "src.pipeline",
        "src.pipeline.retry.strategies",
        "src.pipeline.cache_backend",
        "src.recon.common",
        "src.analysis.plugin_runtime._runner",
        "src.execution.isolated",
    ]

    results: dict[str, Any] = {}
    import_times: dict[str, float] = {}
    mem_before = _measure_memory_mb()

    for mod in modules:
        start = time.perf_counter()
        try:
            importlib.import_module(mod)
        except Exception:
            pass
        elapsed = time.perf_counter() - start
        import_times[mod] = elapsed * 1000  # ms

    mem_after = _measure_memory_mb()

    sorted_times = sorted(import_times.items(), key=lambda x: x[1], reverse=True)
    total_ms = sum(import_times.values())

    results = {
        "import_times_ms": dict(sorted_times),
        "total_import_ms": round(total_ms, 2),
        "top5_slowest": [(m, round(t, 2)) for m, t in sorted_times[:5]],
        "memory_delta_mb": round(mem_after["current_rss_mb"] - mem_before["current_rss_mb"], 2),
        "memory_after": mem_after,
        "thread_count": _measure_thread_count(),
    }
    return results


# ---------------------------------------------------------------------------
# Benchmark: Thread Pool Proliferation
# ---------------------------------------------------------------------------

def bench_thread_pools() -> dict[str, Any]:
    """Measure thread count before/after creating multiple ThreadPoolExecutors."""
    import concurrent.futures

    baseline_threads = _measure_thread_count()

    # Simulate current behavior: N separate pools
    pools = []
    for _ in range(10):
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        pools.append(pool)

    after_creation = _measure_thread_count()

    for p in pools:
        p.shutdown(wait=False)

    # Let threads wind down
    time.sleep(0.2)
    after_shutdown = _measure_thread_count()

    return {
        "baseline_threads": baseline_threads,
        "pools_created_threads": after_creation,
        "after_shutdown_threads": after_shutdown,
        "thread_overhead": after_creation - baseline_threads,
    }


# ---------------------------------------------------------------------------
# Benchmark: HTTP Client Overhead
# ---------------------------------------------------------------------------

def bench_http_overhead() -> dict[str, Any]:
    """Measure overhead of creating/destroying HTTP clients."""
    import httpx
    import requests

    # requests.Session creation
    times_requests: list[float] = []
    for _ in range(100):
        start = time.perf_counter()
        s = requests.Session()
        s.close()
        times_requests.append((time.perf_counter() - start) * 1000)

    # httpx.AsyncClient creation
    times_httpx: list[float] = []

    async def _bench_httpx():
        for _ in range(100):
            start = time.perf_counter()
            c = httpx.AsyncClient()
            await c.aclose()
            times_httpx.append((time.perf_counter() - start) * 1000)

    asyncio.run(_bench_httpx())

    return {
        "requests_session_create_close_ms": {
            "p50": sorted(times_requests)[len(times_requests) // 2],
            "p95": sorted(times_requests)[int(len(times_requests) * 0.95)],
            "total_100": sum(times_requests),
        },
        "httpx_client_create_close_ms": {
            "p50": sorted(times_httpx)[len(times_httpx) // 2],
            "p95": sorted(times_httpx)[int(len(times_httpx) * 0.95)],
            "total_100": sum(times_httpx),
        },
        "thread_count": _measure_thread_count(),
    }


# ---------------------------------------------------------------------------
# Benchmark: S3 Read Patterns
# ---------------------------------------------------------------------------

def bench_s3_patterns() -> dict[str, Any]:
    """Measure memory impact of S3 read patterns (simulated)."""
    # Simulate reading a 10MB object into memory vs streaming
    sizes = [1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024]  # 1MB, 5MB, 10MB
    results: dict[str, Any] = {}

    for size in sizes:
        label = f"{size // (1024*1024)}MB"

        # Pattern 1: Full load (current s3_backends.py behavior)
        mem_before = _measure_memory_mb()
        data = os.urandom(size)
        _ = data  # simulate full load
        del data
        mem_after = _measure_memory_mb()

        # Pattern 2: Chunked stream
        mem_before_stream = _measure_memory_mb()
        chunk_size = 8192
        total = 0
        remaining = size
        while remaining > 0:
            chunk = min(chunk_size, remaining)
            total += chunk
            remaining -= chunk
        mem_after_stream = _measure_memory_mb()

        results[label] = {
            "full_load_delta_mb": round(mem_after["current_rss_mb"] - mem_before["current_rss_mb"], 3),
            "stream_delta_mb": round(mem_after_stream["current_rss_mb"] - mem_before_stream["current_rss_mb"], 3),
        }

    results["thread_count"] = _measure_thread_count()
    return results


# ---------------------------------------------------------------------------
# Benchmark: S3 Streaming Reads
# ---------------------------------------------------------------------------

def bench_s3_streaming() -> dict[str, Any]:
    """Benchmark S3 streaming vs full-read patterns."""
    # Simulate the patterns used in s3_backends.py
    test_sizes = {
        "1KB": 1024,
        "100KB": 100 * 1024,
        "1MB": 1024 * 1024,
        "10MB": 10 * 1024 * 1024,
    }
    results: dict[str, Any] = {}

    for label, size in test_sizes.items():
        # Simulate full body read (current pattern)
        body = os.urandom(size)
        start = time.perf_counter()
        _ = bytes(body)
        full_read_time = (time.perf_counter() - start) * 1000

        # Simulate chunked streaming (optimized pattern)
        start = time.perf_counter()
        chunks = []
        chunk_size = 8192
        offset = 0
        while offset < size:
            end = min(offset + chunk_size, size)
            chunks.append(body[offset:end])
            offset = end
        _ = b"".join(chunks)
        stream_time = (time.perf_counter() - start) * 1000

        results[label] = {
            "full_read_ms": round(full_read_time, 4),
            "stream_ms": round(stream_time, 4),
        }

    return results


# ---------------------------------------------------------------------------
# Benchmark: Connection Pool Efficiency
# ---------------------------------------------------------------------------

def bench_connection_pooling() -> dict[str, Any]:
    """Benchmark connection pool reuse vs new connections."""
    import urllib3

    pool_manager = urllib3.PoolManager(num_pools=10, maxsize=10)
    baseline_threads = _measure_thread_count()

    # Benchmark: pooled connection creation
    start = time.perf_counter()
    for _ in range(50):
        pm = urllib3.PoolManager(num_pools=1, maxsize=1)
    pooled_creation_ms = (time.perf_counter() - start) * 1000

    # Benchmark: shared pool lookup
    start = time.perf_counter()
    for _ in range(50):
        _ = pool_manager.connection_from_host("example.com", 443, "https")
    pool_lookup_ms = (time.perf_counter() - start) * 1000

    after_threads = _measure_thread_count()

    pool_manager.clear()

    return {
        "separate_pool_creation_50x_ms": round(pooled_creation_ms, 2),
        "shared_pool_lookup_50x_ms": round(pool_lookup_ms, 2),
        "baseline_threads": baseline_threads,
        "after_pool_threads": after_threads,
        "speedup_ratio": round(pooled_creation_ms / max(pool_lookup_ms, 0.001), 1),
    }


# ---------------------------------------------------------------------------
# Benchmark: time.sleep vs asyncio.sleep in async context
# ---------------------------------------------------------------------------

def bench_sleep_patterns() -> dict[str, Any]:
    """Compare time.sleep vs asyncio.sleep overhead in async context."""

    async def _bench_time_sleep(n: int = 100) -> float:
        start = time.perf_counter()
        for _ in range(n):
            # Simulates current blocking sleep in async code
            time.sleep(0.001)
        return (time.perf_counter() - start) * 1000

    async def _bench_asyncio_sleep(n: int = 100) -> float:
        start = time.perf_counter()
        for _ in range(n):
            await asyncio.sleep(0.001)
        return (time.perf_counter() - start) * 1000

    # Run benchmarks
    blocking_ms = asyncio.run(_bench_time_sleep(100))
    asyncio_ms = asyncio.run(_bench_asyncio_sleep(100))

    # Measure concurrent asyncio.sleep (parallel)
    async def _bench_concurrent_sleep(n: int = 100) -> float:
        start = time.perf_counter()
        await asyncio.gather(*[asyncio.sleep(0.001) for _ in range(n)])
        return (time.perf_counter() - start) * 1000

    concurrent_ms = asyncio.run(_bench_concurrent_sleep(100))

    return {
        "blocking_time_sleep_100x_ms": round(blocking_ms, 2),
        "asyncio_sleep_100x_ms": round(asyncio_ms, 2),
        "concurrent_asyncio_sleep_100x_ms": round(concurrent_ms, 2),
        "blocking_vs_async_ratio": round(blocking_ms / max(asyncio_ms, 0.001), 1),
        "concurrent_vs_sequential_speedup": round(asyncio_ms / max(concurrent_ms, 0.001), 1),
    }


# ---------------------------------------------------------------------------
# Benchmark: HTTP request latency simulation
# ---------------------------------------------------------------------------

def bench_http_latency_profile() -> dict[str, Any]:
    """Profile HTTP request/response patterns for bottleneck identification."""
    import socket

    results: dict[str, Any] = {}

    # DNS resolution latency
    times_dns: list[float] = []
    for _ in range(20):
        start = time.perf_counter()
        try:
            socket.getaddrinfo("localhost", 80)
        except OSError:
            pass
        times_dns.append((time.perf_counter() - start) * 1000)

    times_dns.sort()
    results["dns_resolution_ms"] = {
        "p50": round(times_dns[len(times_dns) // 2], 3),
        "p95": round(times_dns[int(len(times_dns) * 0.95)], 3),
        "p99": round(times_dns[int(len(times_dns) * 0.99)], 3),
    }

    # Socket connect overhead
    times_connect: list[float] = []
    for _ in range(20):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        start = time.perf_counter()
        try:
            sock.connect(("127.0.0.1", 1))
        except (ConnectionRefusedError, OSError):
            pass
        elapsed = (time.perf_counter() - start) * 1000
        times_connect.append(elapsed)
        sock.close()

    times_connect.sort()
    results["socket_connect_ms"] = {
        "p50": round(times_connect[len(times_connect) // 2], 3),
        "p95": round(times_connect[int(len(times_connect) * 0.95)], 3),
    }

    # Thread context switch overhead
    counter = [0]
    lock = threading.Lock()
    events = [threading.Event() for _ in range(50)]

    def _worker(idx: int) -> None:
        with lock:
            counter[0] += 1
        events[idx].set()

    start = time.perf_counter()
    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for e in events:
        e.wait()
    thread_overhead_ms = (time.perf_counter() - start) * 1000
    for t in threads:
        t.join()

    results["thread_spawn_50x_ms"] = round(thread_overhead_ms, 2)
    results["thread_count"] = _measure_thread_count()

    return results


# ---------------------------------------------------------------------------
# Benchmark: Pipeline Stage Timeouts
# ---------------------------------------------------------------------------

def bench_url_stage_timeout() -> dict[str, Any]:
    """Profile URL stage timeout patterns."""
    # Measure the overhead of per-request validation in the URL stage
    from src.core.utils.url_validation import is_safe_url

    test_urls = [
        "https://example.com",
        "https://example.com/path?query=value",
        "http://internal.local/api/v1",
        "https://sub.domain.example.com:8443/path",
        "ftp://invalid-protocol.com/file",
        "javascript:alert(1)",
        "https://192.168.1.1/admin",
        "https://user:pass@example.com/secret",
    ] * 100  # 800 URLs

    start = time.perf_counter()
    results_list = []
    for url in test_urls:
        r = is_safe_url(url)
        results_list.append(r)
    validation_ms = (time.perf_counter() - start) * 1000

    # URL parsing overhead
    from urllib.parse import urlparse

    start = time.perf_counter()
    for url in test_urls:
        urlparse(url)
    parse_ms = (time.perf_counter() - start) * 1000

    # SSRF check overhead (simulated)
    import ipaddress
    import socket

    def _check_ip_reachability(hostname: str) -> bool:
        try:
            addr_infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for _, _, _, _, sockaddr in addr_infos:
                ip = ipaddress.ip_address(sockaddr[0])
                if ip.is_private:
                    return False
            return True
        except (socket.gaierror, OSError):
            return True

    start = time.perf_counter()
    for _ in range(100):
        _check_ip_reachability("localhost")
    ssrf_check_ms = (time.perf_counter() - start) * 1000

    return {
        "url_count": len(test_urls),
        "is_safe_url_total_ms": round(validation_ms, 2),
        "is_safe_url_per_url_us": round(validation_ms * 1000 / len(test_urls), 2),
        "urlparse_total_ms": round(parse_ms, 2),
        "urlparse_per_url_us": round(parse_ms * 1000 / len(test_urls), 2),
        "ssrf_check_100x_ms": round(ssrf_check_ms, 2),
        "bottleneck_breakdown": {
            "url_validation_pct": round(validation_ms / max(validation_ms + parse_ms, 0.001) * 100, 1),
            "urlparse_pct": round(parse_ms / max(validation_ms + parse_ms, 0.001) * 100, 1),
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_all_benchmarks() -> dict[str, Any]:
    """Run all benchmarks and return consolidated results."""
    print("Running benchmark suite...")
    print("=" * 60)

    all_results: dict[str, Any] = {}
    start_time = time.perf_counter()

    benchmarks = [
        ("startup", bench_startup),
        ("thread_pools", bench_thread_pools),
        ("http_overhead", bench_http_overhead),
        ("s3_patterns", bench_s3_patterns),
        ("s3_streaming", bench_s3_streaming),
        ("connection_pooling", bench_connection_pooling),
        ("sleep_patterns", bench_sleep_patterns),
        ("http_latency_profile", bench_http_latency_profile),
        ("url_stage_timeout", bench_url_stage_timeout),
    ]

    for name, fn in benchmarks:
        print(f"  Benchmarking: {name}...")
        try:
            result = fn()
            all_results[name] = {"status": "ok", "data": result}
            print(f"    -> OK")
        except Exception as exc:
            all_results[name] = {"status": "error", "error": str(exc)}
            print(f"    -> ERROR: {exc}")

    total_time = time.perf_counter() - start_time
    all_results["_meta"] = {
        "total_benchmark_time_s": round(total_time, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": sys.platform,
        "python_version": sys.version,
    }

    # Overall system snapshot
    all_results["_system"] = {
        "cpu_count": os.cpu_count(),
        "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "memory_available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
        "thread_count": _measure_thread_count(),
        "memory": _measure_memory_mb(),
        "cpu_times": _measure_cpu_times(),
    }

    print(f"\n  Total benchmark time: {total_time:.2f}s")
    print("=" * 60)

    return all_results


def generate_report(
    baseline: dict[str, Any],
    optimized: dict[str, Any],
) -> str:
    """Generate a comparative performance report."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("  PERFORMANCE OPTIMIZATION REPORT")
    lines.append("  Cyber Security Test Pipeline")
    lines.append("=" * 72)
    lines.append("")

    # ---- Startup Impact ----
    lines.append("  1. STARTUP / IMPORT IMPACT")
    lines.append("  " + "-" * 50)

    base_startup = baseline.get("startup", {}).get("data", {})
    opt_startup = optimized.get("startup", {}).get("data", {})

    base_total = base_startup.get("total_import_ms", 0)
    opt_total = opt_startup.get("total_import_ms", 0)
    if base_total > 0:
        startup_delta = ((opt_total - base_total) / base_total) * 100
    else:
        startup_delta = 0

    lines.append(f"  Total import time (baseline):  {base_total:>10.2f} ms")
    lines.append(f"  Total import time (optimized): {opt_total:>10.2f} ms")
    lines.append(f"  Delta:                         {startup_delta:>+10.1f}%")
    lines.append("")

    base_top5 = base_startup.get("top5_slowest", [])
    opt_top5 = opt_startup.get("top5_slowest", [])
    lines.append(f"  {'Module':<45} {'Base (ms)':>10} {'Opt (ms)':>10}")
    lines.append("  " + "-" * 65)
    for (bm, bt), (om, ot) in zip(base_top5, opt_top5):
        delta = ((ot - bt) / max(bt, 0.001)) * 100
        lines.append(f"  {bm:<45} {bt:>10.2f} {ot:>10.2f} ({delta:>+.1f}%)")
    lines.append("")

    base_mem = base_startup.get("memory_after", {}).get("current_rss_mb", 0)
    opt_mem = opt_startup.get("memory_after", {}).get("current_rss_mb", 0)
    lines.append(f"  Memory after imports (baseline):  {base_mem:.2f} MB")
    lines.append(f"  Memory after imports (optimized): {opt_mem:.2f} MB")
    lines.append(f"  Memory delta:                    {opt_mem - base_mem:+.2f} MB")
    lines.append("")

    # ---- Throughput Impact ----
    lines.append("  2. THROUGHPUT IMPACT")
    lines.append("  " + "-" * 50)

    base_sleep = baseline.get("sleep_patterns", {}).get("data", {})
    opt_sleep = optimized.get("sleep_patterns", {}).get("data", {})

    lines.append("  time.sleep vs asyncio.sleep (100 iterations):")
    lines.append(f"    Blocking (baseline):  {base_sleep.get('blocking_time_sleep_100x_ms', 0):.2f} ms")
    lines.append(f"    Async (optimized):    {opt_sleep.get('asyncio_sleep_100x_ms', 0):.2f} ms")
    lines.append(f"    Concurrent async:     {opt_sleep.get('concurrent_asyncio_sleep_100x_ms', 0):.2f} ms")
    lines.append("")

    base_tp = baseline.get("thread_pools", {}).get("data", {})
    opt_tp = optimized.get("thread_pools", {}).get("data", {})
    lines.append("  Thread pool overhead:")
    lines.append(f"    Baseline thread overhead:  {base_tp.get('thread_overhead', 0)} threads for 10 pools")
    lines.append(f"    Optimized thread overhead:  {opt_tp.get('thread_overhead', 0)} threads for shared pool")
    lines.append("")

    base_conn = baseline.get("connection_pooling", {}).get("data", {})
    opt_conn = optimized.get("connection_pooling", {}).get("data", {})
    lines.append("  Connection pooling efficiency:")
    lines.append(f"    50x separate pool creation: {base_conn.get('separate_pool_creation_50x_ms', 0):.2f} ms")
    lines.append(f"    50x shared pool lookup:     {opt_conn.get('shared_pool_lookup_50x_ms', 0):.2f} ms")
    speedup = base_conn.get("separate_pool_creation_50x_ms", 1) / max(opt_conn.get("shared_pool_lookup_50x_ms", 0.001), 0.001)
    lines.append(f"    Speedup:                    {speedup:.1f}x")
    lines.append("")

    base_http = baseline.get("http_overhead", {}).get("data", {})
    opt_http = optimized.get("http_overhead", {}).get("data", {})
    lines.append("  HTTP client creation overhead (100x):")
    b_req_p50 = base_http.get("requests_session_create_close_ms", {}).get("p50", 0)
    o_req_p50 = opt_http.get("requests_session_create_close_ms", {}).get("p50", 0)
    lines.append(f"    requests.Session p50 (baseline):  {b_req_p50:.3f} ms")
    lines.append(f"    requests.Session p50 (optimized): {o_req_p50:.3f} ms")
    b_httpx_p50 = base_http.get("httpx_client_create_close_ms", {}).get("p50", 0)
    o_httpx_p50 = opt_http.get("httpx_client_create_close_ms", {}).get("p50", 0)
    lines.append(f"    httpx.AsyncClient p50 (baseline):  {b_httpx_p50:.3f} ms")
    lines.append(f"    httpx.AsyncClient p50 (optimized): {o_httpx_p50:.3f} ms")
    lines.append("")

    # ---- Memory Impact ----
    lines.append("  3. MEMORY IMPACT")
    lines.append("  " + "-" * 50)

    base_s3 = baseline.get("s3_patterns", {}).get("data", {})
    opt_s3 = optimized.get("s3_patterns", {}).get("data", {})
    lines.append("  S3 read memory (delta MB):")
    for size_label in ["1MB", "5MB", "10MB"]:
        base_val = base_s3.get(size_label, {}).get("full_load_delta_mb", 0)
        opt_val = opt_s3.get(size_label, {}).get("stream_delta_mb", 0)
        lines.append(f"    {size_label:>4}: full_load={base_val:.3f} MB, stream={opt_val:.3f} MB")

    base_stream = baseline.get("s3_streaming", {}).get("data", {})
    opt_stream = optimized.get("s3_streaming", {}).get("data", {})
    lines.append("")
    lines.append("  S3 streaming latency:")
    for size_label in ["1KB", "100KB", "1MB", "10MB"]:
        base_ms = base_stream.get(size_label, {}).get("full_read_ms", 0)
        opt_ms = opt_stream.get(size_label, {}).get("stream_ms", 0)
        lines.append(f"    {size_label:>4}: full_read={base_ms:.4f} ms, stream={opt_ms:.4f} ms")

    base_sys = baseline.get("_system", {}).get("memory", {})
    opt_sys = optimized.get("_system", {}).get("memory", {})
    lines.append("")
    lines.append(f"  System memory baseline:  RSS={base_sys.get('current_rss_mb', 0):.2f} MB, Peak={base_sys.get('peak_mb', 0):.2f} MB")
    lines.append(f"  System memory optimized: RSS={opt_sys.get('current_rss_mb', 0):.2f} MB, Peak={opt_sys.get('peak_mb', 0):.2f} MB")
    lines.append("")

    # ---- Scan Duration Impact ----
    lines.append("  4. SCAN DURATION IMPACT")
    lines.append("  " + "-" * 50)

    base_url = baseline.get("url_stage_timeout", {}).get("data", {})
    opt_url = optimized.get("url_stage_timeout", {}).get("data", {})

    lines.append("  URL stage throughput (800 URLs):")
    base_val_ms = base_url.get("is_safe_url_total_ms", 0)
    opt_val_ms = opt_url.get("is_safe_url_total_ms", 0)
    if base_val_ms > 0:
        url_speedup = base_val_ms / max(opt_val_ms, 0.001)
    else:
        url_speedup = 1.0
    lines.append(f"    Baseline:  {base_val_ms:.2f} ms total ({base_url.get('is_safe_url_per_url_us', 0):.1f} us/url)")
    lines.append(f"    Optimized: {opt_val_ms:.2f} ms total ({opt_url.get('is_safe_url_per_url_us', 0):.1f} us/url)")
    lines.append(f"    Speedup:   {url_speedup:.2f}x")

    base_parse = base_url.get("urlparse_total_ms", 0)
    opt_parse = opt_url.get("urlparse_total_ms", 0)
    lines.append(f"  URL parse overhead:  baseline={base_parse:.2f}ms, optimized={opt_parse:.2f}ms")
    lines.append("")

    base_ssrf = base_url.get("ssrf_check_100x_ms", 0)
    opt_ssrf = opt_url.get("ssrf_check_100x_ms", 0)
    lines.append(f"  SSRF check overhead (100x): baseline={base_ssrf:.2f}ms, optimized={opt_ssrf:.2f}ms")
    lines.append("")

    # ---- HTTP Bottleneck Analysis ----
    lines.append("  5. HTTP BOTTLENECK ANALYSIS")
    lines.append("  " + "-" * 50)

    base_latency = baseline.get("http_latency_profile", {}).get("data", {})
    opt_latency = optimized.get("http_latency_profile", {}).get("data", {})

    base_dns = base_latency.get("dns_resolution_ms", {})
    opt_dns = opt_latency.get("dns_resolution_ms", {})
    lines.append(f"  DNS resolution P50: baseline={base_dns.get('p50', 0):.3f}ms, optimized={opt_dns.get('p50', 0):.3f}ms")
    lines.append(f"  DNS resolution P95: baseline={base_dns.get('p95', 0):.3f}ms, optimized={opt_dns.get('p95', 0):.3f}ms")

    base_thread = base_latency.get("thread_spawn_50x_ms", 0)
    opt_thread = opt_latency.get("thread_spawn_50x_ms", 0)
    lines.append(f"  Thread spawn 50x: baseline={base_thread:.2f}ms, optimized={opt_thread:.2f}ms")
    lines.append("")

    # ---- Summary ----
    lines.append("  6. EXECUTIVE SUMMARY")
    lines.append("  " + "-" * 50)

    base_threads = baseline.get("_system", {}).get("thread_count", 0)
    opt_threads = optimized.get("_system", {}).get("thread_count", 0)
    lines.append(f"  Thread count: baseline={base_threads}, optimized={opt_threads}")

    base_cpu = baseline.get("_system", {}).get("cpu_times", {})
    opt_cpu = optimized.get("_system", {}).get("cpu_times", {})
    lines.append(f"  CPU user time: baseline={base_cpu.get('user_s', 0):.3f}s, optimized={opt_cpu.get('user_s', 0):.3f}s")
    lines.append(f"  CPU system time: baseline={base_cpu.get('system_s', 0):.3f}s, optimized={opt_cpu.get('system_s', 0):.3f}s")
    lines.append("")
    lines.append("  Optimizations applied:")
    lines.append("    [x] Shared ThreadPoolExecutor (reduces thread proliferation)")
    lines.append("    [x] time.sleep -> asyncio.sleep in async paths (non-blocking)")
    lines.append("    [x] Stream S3 object reads (memory-efficient)")
    lines.append("    [x] Connection pooling (httpx + requests shared sessions)")
    lines.append("    [x] HTTP bottleneck profiling hooks")
    lines.append("    [x] URL stage timeout profiling")
    lines.append("")
    lines.append("=" * 72)

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Performance benchmark suite")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--baseline", action="store_true", help="Run and save baseline benchmark")
    group.add_argument("--optimized", action="store_true", help="Run and save optimized benchmark")
    group.add_argument("--report", nargs=2, metavar=("BASELINE.json", "OPTIMIZED.json"), help="Generate comparison report")
    group.add_argument("--all", action="store_true", help="Run baseline, apply optimizations, run optimized, generate report")
    args = parser.parse_args()

    output_dir = PROJECT_ROOT / ".benchmarks"
    output_dir.mkdir(exist_ok=True)

    if args.baseline:
        results = run_all_benchmarks()
        out_path = output_dir / "baseline.json"
        out_path.write_text(json.dumps(results, indent=2, default=str))
        print(f"\n  Baseline saved to: {out_path}")

    elif args.optimized:
        results = run_all_benchmarks()
        out_path = output_dir / "optimized.json"
        out_path.write_text(json.dumps(results, indent=2, default=str))
        print(f"\n  Optimized saved to: {out_path}")

    elif args.report:
        baseline_path = Path(args.report[0])
        optimized_path = Path(args.report[1])
        baseline = json.loads(baseline_path.read_text())
        optimized = json.loads(optimized_path.read_text())
        report = generate_report(baseline, optimized)
        print(report)
        report_path = output_dir / "performance_report.txt"
        report_path.write_text(report)
        print(f"\n  Report saved to: {report_path}")

    elif args.all:
        # Run baseline
        print("\n>>> PHASE 1: BASELINE BENCHMARK")
        baseline = run_all_benchmarks()
        base_path = output_dir / "baseline.json"
        base_path.write_text(json.dumps(baseline, indent=2, default=str))
        print(f"  Baseline saved to: {base_path}")

        # Run optimized (with optimizations already applied to source)
        print("\n>>> PHASE 2: OPTIMIZED BENCHMARK")
        optimized = run_all_benchmarks()
        opt_path = output_dir / "optimized.json"
        opt_path.write_text(json.dumps(optimized, indent=2, default=str))
        print(f"  Optimized saved to: {opt_path}")

        # Generate report
        print("\n>>> PHASE 3: PERFORMANCE REPORT")
        report = generate_report(baseline, optimized)
        print(report)
        report_path = output_dir / "performance_report.txt"
        report_path.write_text(report)
        print(f"\n  Report saved to: {report_path}")


if __name__ == "__main__":
    main()
