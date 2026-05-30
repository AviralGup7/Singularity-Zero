# Bloom Frontier Benchmark Notes

## Scope

This file tracks the Bloom frontier optimization work for `src/core/frontier/bloom.py`.
The checked-in benchmark suite is offline-only and does not call external services.

## Profiling Workflow

The performance of `src/core/frontier/bloom.py` is exercised and verified indirectly via bloom-adjacent unit and integration tests (such as Cache Routing in `test_cache.py` and Self-Healing in `test_self_healing.py`), as there are no dedicated `test_bloom` unit test files in the repository. The following commands run the test suites:

```powershell
# Run the full backend test suite (includes bloom-adjacent e2e tests)
pytest

# Run only e2e tests (faster, covers mesh and state-compaction paths)
pytest tests/e2e/
```

> **Note on load benchmarks:** A dedicated performance-only load file (`test_bloom_optimized.py`)
> was planned to exercise the Bloom filter against a synthetic 10 M URL corpus. That file is not
> present in this workspace; the profiling notes in this document describe the analytical approach
> for when such a harness is added. No synthetic dataset of 10 M real or generated URLs is
> checked in. If you build or acquire such a corpus, run it against the existing bundled smoke
> harness rather than creating an additional one: `pytest tests/ -v --tb=short`.

### Analytical profiling (requires a real corpus)

If you have a local URL corpus and want to profile the hot path directly:

```powershell
# Generate a new cProfile snapshot for the bloom hot path
python -m cProfile -o output/bloom_process_urls.cprofile -m pytest tests/ --co -q
# Inspect with snakeviz or similar
```

## Current Bottlenecks

The original implementation did one Python loop per URL and one nested Python loop per hash round. That made membership checks scale with `url_count * hash_count` at Python bytecode speed.

The optimized path moves byte-index calculation, mask generation, membership checks, and packed-bit writes into NumPy arrays. The remaining Python-level hot spot is MurmurHash3 seed generation because `mmh3.hash64` does not expose a true bulk NumPy ufunc. A Cython or C extension should only replace that path if the benchmark shows a measured win beyond the fallback thresholds.

Primary allocation risks now come from chunk-local string normalization and offset matrices. Adaptive chunk sizing uses available RAM minus a 2GB safety buffer, with lower and upper bounds to avoid tiny cache-thrashing arrays or oversized temporaries.

## Full Dataset Status

No real 10M URL corpus is checked into this workspace. The full benchmark path generates deterministic offline URLs unless a future harness is pointed at a local corpus. Results from generated data are useful for throughput and memory pressure, but production corpus runs should be recorded here separately.

## Fallback Rule

If the optimized path is more than 2% slower than the previous implementation, or increases memory by more than 10%, keep only safe non-throughput changes such as profiling docs, reconciliation APIs, and UI observability. Revert the Bloom processing strategy and record the decision in the commit description.
