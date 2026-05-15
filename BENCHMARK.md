# Bloom Frontier Benchmark Notes

## Scope

This file tracks the Bloom frontier optimization work for `src/core/frontier/bloom.py`.
The checked-in benchmark suite is offline-only and does not call external services.

## Profiling Workflow

Run the bounded smoke benchmark:

```powershell
pytest tests/performance/test_bloom_optimized.py -m benchmark
```

Run the full 10M URL path on a local machine with enough RAM:

```powershell
$env:BLOOM_PERF_FULL = "1"
pytest tests/performance/test_bloom_optimized.py -m benchmark
```

Recommended profiling commands:

```powershell
python -m cProfile -o output/bloom_process_urls.cprofile -m pytest tests/performance/test_bloom_optimized.py::test_process_urls_vectorized_smoke_throughput
python -m line_profiler tests/performance/test_bloom_optimized.py
```

## Current Bottlenecks

The original implementation did one Python loop per URL and one nested Python loop per hash round. That made membership checks scale with `url_count * hash_count` at Python bytecode speed.

The optimized path moves byte-index calculation, mask generation, membership checks, and packed-bit writes into NumPy arrays. The remaining Python-level hot spot is MurmurHash3 seed generation because `mmh3.hash64` does not expose a true bulk NumPy ufunc. A Cython or C extension should only replace that path if the benchmark shows a measured win beyond the fallback thresholds.

Primary allocation risks now come from chunk-local string normalization and offset matrices. Adaptive chunk sizing uses available RAM minus a 2GB safety buffer, with lower and upper bounds to avoid tiny cache-thrashing arrays or oversized temporaries.

## Full Dataset Status

No real 10M URL corpus is checked into this workspace. The full benchmark path generates deterministic offline URLs unless a future harness is pointed at a local corpus. Results from generated data are useful for throughput and memory pressure, but production corpus runs should be recorded here separately.

## Fallback Rule

If the optimized path is more than 2% slower than the previous implementation, or increases memory by more than 10%, keep only safe non-throughput changes such as profiling docs, reconciliation APIs, and UI observability. Revert the Bloom processing strategy and record the decision in the commit description.
