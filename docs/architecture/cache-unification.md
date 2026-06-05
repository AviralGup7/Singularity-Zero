# Cache Unification — Design Doc

## Problem

The pipeline currently maintains three uncoordinated persistence layers:

1. `src/pipeline/cache.py` — file-based JSON / gzip cache with atomic writes
   (`load_cached_json`, `save_cached_json`, `load_cached_set`, `save_cached_set`,
   `response_cache_fresh`).
2. `src/pipeline/cache_backend.py` — `PersistentCache`: SQLite (WAL journal,
   busy-timeout retry, TTL, `prune_prefix`, thread-local connections).
3. `src/pipeline/storage.py::write_json` — atomic JSON file writes used for
   pipeline outputs.

There is **no coherence protocol** between them:

| Symptom | Mechanism |
|---|---|
| Stale tool result returned | `cache.py` write invisible to `PersistentCache.get()` |
| Eviction asymmetry | `PersistentCache.prune_oldest()` cannot evict file-cache entries |
| Probe storms | Two parallel stages issue the same `live_hosts` subprocess because there is no single-flight gate |
| Resume eviction | Long-running `active_scan` evicts subdomain entries shared via the global LRU |
| Latency cliff | TTL miss in `response_cache_fresh()` blocks the caller while it re-fetches |

## Goals

1. **Single key space.** All callers address cached data by `(namespace, key)`;
   the facade decides which backend stores the bytes.
2. **Routing by data shape.** Structured / small / hot → SQLite. Blob / large /
   cold → file cache. The caller does not choose the backend.
3. **Coherent invalidation.** Deleting a key in the facade removes every
   physical copy.
4. **Single-flight semantics.** Concurrent `get_or_compute(key, …)` calls for
   the same key issue at most one upstream fetch.
5. **Priority-aware eviction.** Resume / checkpoint entries cannot be evicted
   under pressure from transient tool output.
6. **Stale-while-revalidate.** Hot, slowly-changing entries (crt.sh, passive
   HTTP responses) return cached data immediately and refresh in the
   background.

Non-goal: replace `src/infrastructure/cache/CacheManager`. That is the
multi-tier system used by `src/analysis` and downstream services. The
facade introduced here lives in `src/pipeline/` and addresses only the
pipeline-level duality.

## Unified key schema

```
<namespace>:<scope>:<identifier>
```

| Namespace        | Routes to     | Examples                                    |
|------------------|---------------|---------------------------------------------|
| `probe`          | SQLite        | `probe:<target>:<host>`                     |
| `http_response`  | SQLite (meta) + file (body when > 16 KB) | `http_response:<target>:<sha256(url)>` |
| `screenshot`     | File          | `screenshot:<target>:<sha256(url)>.png`     |
| `subdomain`      | SQLite        | `subdomain:<target>:<source>`               |
| `url`            | SQLite        | `url:<target>:<source>`                     |
| `resume`         | SQLite (`CRITICAL`) | `resume:<run_id>:<stage>`             |
| `checkpoint`     | SQLite (`CRITICAL`) | `checkpoint:<run_id>:<stage>`         |
| `tool_output`    | File          | `tool_output:<run_id>:<tool>:<invocation>`  |
| `passive_record` | File (legacy) | maps to `load_cached_json` paths            |

Anything not matching a known namespace is rejected by the facade in
strict mode and routed to SQLite in lenient mode (default during
migration).

## Backend selection rules

```
def route(namespace, *, payload_size_hint=None) -> Backend:
    cfg = NAMESPACE_ROUTING[namespace]
    if cfg.always == Backend.SQLITE: return Backend.SQLITE
    if cfg.always == Backend.FILE:   return Backend.FILE
    if cfg.split_threshold_bytes is not None and payload_size_hint is not None:
        if payload_size_hint >= cfg.split_threshold_bytes:
            return Backend.FILE
        return Backend.SQLITE
    return cfg.default
```

For `http_response`, metadata (headers, status, hash, `cached_at_epoch`)
goes to SQLite, body bytes go to file when over the split threshold —
the SQLite row stores the file path. The facade reassembles on read.

## Coherence protocol

- **set(key, value)** writes to exactly one backend (the routed one) plus
  a routing-index row in SQLite (`cache_routing(key, backend, path,
  size_bytes, priority)`).
- **get(key)** consults the routing index first, then reads from the
  routed backend; missing or corrupt physical entries are scrubbed from
  the index on read.
- **delete(key)** removes the physical entry and the index row atomically
  (one SQLite transaction wrapping the file `os.unlink`).
- **prune_prefix(prefix)** walks the routing index, deleting from both
  backends in lockstep.
- **cleanup_expired()** drops expired SQLite entries and deletes any
  index rows pointing at missing files.

## Priority

`CachePriority` enum:

| Level       | Eviction order         | Default for           |
|-------------|------------------------|-----------------------|
| `CRITICAL`  | never auto-evicted     | `resume`, `checkpoint`|
| `NORMAL`    | LRU after `TRANSIENT`  | most namespaces       |
| `TRANSIENT` | LRU first              | `tool_output`         |

`prune_oldest(n)` selects victims with `ORDER BY priority_rank DESC,
created_at ASC` so transient entries vanish before normal entries, and
critical entries are never touched. Existing rows migrate to `NORMAL`.

## Single-flight (`CoalescingCacheWrapper`)

An async wrapper that keeps an `asyncio.Lock` per in-flight key.

```python
wrapper = CoalescingCacheWrapper(unified_cache)
record = await wrapper.get_or_compute(
    key, ttl=600, compute=lambda: probe_live_host(host)
)
```

When two tasks request the same key concurrently, the second awaits the
first's lock, then reads the value from cache without re-running
`compute`. Locks are removed from the registry as soon as the original
in-flight task completes (success or exception).

## Stale-while-revalidate

`response_cache_fresh` gains a new mode:

```python
status = response_cache_fresh(
    record,
    ttl_hours=24,
    swr_grace_hours=24,
)
# status is one of: FRESH, STALE_REFRESHABLE, EXPIRED
```

Callers that want SWR check for `STALE_REFRESHABLE`, return the cached
value, and schedule a background refresh through a `RefreshScheduler`
hook (asyncio task by default). The hook deduplicates refreshes by key,
so a thundering herd produces one fetch.

## Migration plan

| Phase | Scope                                    | Risk |
|-------|------------------------------------------|------|
| 1     | Land `UnifiedCache` + design doc + shim  | low  |
| 2     | Add `CoalescingCacheWrapper`             | low  |
| 3     | Add priority schema (additive column)    | medium (DB migration) |
| 4     | SWR mode added to `response_cache_fresh` (new param, default off) | low |
| 5     | Migrate `live_hosts.py` to facade        | medium |
| 6     | Migrate `passive/runtime.py` to facade   | medium |
| 7     | Remove deprecation shims                 | low  |

Phases 1–4 are landed by this change. Phases 5–7 are follow-up work.

## Backwards compatibility

The legacy module-level functions (`load_cached_json`, `save_cached_json`,
`load_cached_set`, `save_cached_set`) continue to work and emit
`DeprecationWarning`. `PersistentCache` continues to work unchanged
except for the additive `priority` column (default `NORMAL`).
