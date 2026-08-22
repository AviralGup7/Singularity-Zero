# Cache Unification — Architecture & Design

## Problem & Motivation

The pipeline previously maintained uncoordinated persistence layers across multiple subsystems:
1. `src/pipeline/cache.py` — File-based JSON / gzip cache with atomic writes (`load_cached_json`, `save_cached_json`, `response_cache_fresh`).
2. `src/pipeline/cache_backend.py` — SQLite `PersistentCache` (WAL journal, busy-timeout retry, TTL, `prune_prefix`).
3. Output / artifact stores for pipeline outputs and checkpoints.

The unified caching architecture consolidates these mechanisms into a high-performance, tiered caching facade (`src/pipeline/unified_cache/` and `src/cache/`).

---

## Architectural Goals & Guarantees

1. **Unified Key Namespace**: All callers address cached entries via structured composite keys: `<namespace>:<scope>:<identifier>`.
2. **Dynamic Backend Routing**:
   - Small, structured, high-frequency metadata → SQLite / Memory LRU.
   - Large blobs, raw responses, screenshots → File / Object Storage.
3. **Atomic Coherent Invalidation**: Deleting a key removes its associated metadata and underlying disk storage in a single operation.
4. **Single-Flight Coalescing (`CoalescingCacheWrapper`)**: Concurrent stage queries for identical keys share a single upstream fetch lock, eliminating probe storms and redundant subprocess executions.
5. **Priority-Aware Eviction**: Cache entries are tagged with `CachePriority`:
   - `CRITICAL`: Scan checkpoints, WAL states, and resume anchors (never auto-evicted).
   - `NORMAL`: Discovery and reconnaissance outputs.
   - `TRANSIENT`: Raw ephemeral tool logs (evicted first during memory pressure).
6. **Stale-While-Revalidate (SWR)**: Slowly-changing external OSINT queries (e.g. `crt.sh`, WHOIS) return cached results instantly while triggering asynchronous background refresh tasks.

---

## Unified Key Schema

```text
<namespace>:<scope>:<identifier>
```

| Namespace | Storage Backend | Typical Use Case |
|---|---|---|
| `probe` | SQLite / Memory | `probe:<target>:<host>` (Live host availability checks) |
| `http_response` | SQLite (meta) + File (body > 16KB) | `http_response:<target>:<sha256(url)>` |
| `screenshot` | File | `screenshot:<target>:<sha256(url)>.png` |
| `subdomain` | SQLite | `subdomain:<target>:<source>` |
| `url` | SQLite | `url:<target>:<source>` |
| `resume` | SQLite (`CRITICAL`) | `resume:<run_id>:<stage>` |
| `checkpoint` | SQLite (`CRITICAL`) | `checkpoint:<run_id>:<stage>` |
| `tool_output` | File (`TRANSIENT`) | `tool_output:<run_id>:<tool>:<invocation>` |

---

## Single-Flight Concurrency Control

```python
from src.pipeline.unified_cache.coalescing import CoalescingCacheWrapper

wrapper = CoalescingCacheWrapper(unified_cache)
record = await wrapper.get_or_compute(
    key="probe:example.com:api.example.com",
    ttl=600,
    compute=lambda: probe_live_host("api.example.com"),
)
```

When multiple parallel stage workers request the same target concurrently, subsequent tasks await the first task's lock, eliminating redundant probes and upstream rate-limit penalties.
