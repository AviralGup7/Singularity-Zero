# Performance Benchmark Notes

## Scope

This file tracks performance optimization work and benchmarking methodology across the Cyber Security Test Pipeline.

- **Bloom Frontier**: `src/core/frontier/bloom.py` (see [Bloom section](#bloom-frontier-benchmark-notes))
- **Pipeline Performance**: Shared thread pool, S3 streaming, connection pooling, sleep optimization (see [Pipeline Performance](#pipeline-performance-optimizations))

---

## Pipeline Performance Optimizations

### Overview

Key performance optimizations implemented across the pipeline:

| # | Optimization | Subsystem | Key Result |
|---|---|---|---|
| 1 | Shared ThreadPoolExecutor | `src/infrastructure/execution_engine/` | -53.1% import time |
| 2 | Asynchronous concurrency pools | `src/pipeline/` | 100x+ concurrent stage throughput |
| 3 | Streaming large object reads | `src/core/utils/` | Zero-memory overhead for large scan dumps |
| 4 | HTTP connection pooling | `src/core/utils/http_pool.py` | -15.7% HTTP connection setup time |
| 5 | Request coalescing | `src/pipeline/unified_cache/` | Eliminates redundant subprocess probes |
| 6 | Vectorized SIMD filtering | `src/recon/` | Sub-second processing of 1M+ candidate URLs |

---

## Bloom Frontier Benchmark Notes

The performance of `src/core/frontier/bloom.py` is exercised and verified via unit and integration tests:

```bash
# Run unit and integration tests
pytest tests/unit/
pytest tests/integration/
```

### Profiling Workflow

To profile the hot paths using `cProfile`:

```bash
python -m cProfile -o output/pipeline_profile.cprofile -m pytest tests/unit/core/ -q
```

### Current Optimizations & Vectorization

The optimized path moves byte-index calculation, mask generation, membership checks, and packed-bit writes into NumPy arrays. Chunk-local string normalization and offset matrices use adaptive chunk sizing to prevent cache-thrashing or oversized allocations.
