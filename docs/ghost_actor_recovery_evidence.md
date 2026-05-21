# Ghost-Actor Mesh Recovery Evidence

Date: 2026-05-21

## Recovery Contract

The frontier recovery path now uses a single durable rule: every resumed actor starts from the latest complete CRDT snapshot and replays only WAL entries after that snapshot cursor. Replayed entries carry `_wal_id` into `NeuralState`, so a duplicate Redis stream delivery or repeated actor `recover` message is ignored after the first successful merge.

## Snapshot Format

`NeuralState.to_crdt_snapshot()` emits `neural-state-crdt-v2`:

- Full LWW element maps for `subdomains`, `urls`, and `findings`, including tombstones.
- `last_wal_id` and `applied_wal_ids` so cold-start replay begins after the last consistent cursor.
- Metadata and creation time for auditability.
- A stable SHA-256 digest when persisted by `FrontierWAL.persist_snapshot()`.

Legacy value-only snapshots are still accepted by `NeuralState.from_crdt_snapshot()` and `StageResult.restore()`.

## CRDT Compaction Gating & Radix Sort

To prevent event velocity issues from degrading performance:
- **AIMD Compaction Budgeting**: A new `CRDTCompactionBudget` class implements Additive Increase / Multiplicative Decrease (AIMD) logic to dynamically adjust the allowed time budget (in milliseconds) based on actual processing latency against target bounds.
- **Fast-Path Radix Sort**: An $O(N)$ LSD integer-based radix sort `radix_sort_timestamps` is introduced to rapidly sort tombstone elements by their floating-point timestamps without standard comparison-sort overhead.
- **Compaction Gating**: `compact_state()` transparently gates tombstone pruning under the budget, ensuring the system remains responsive.

## WAL Dual-Commit & CRC64 Integrity

A high-reliability write-ahead logging (WAL) architecture has been deployed:
- **Dual-Commit Protocol**: `FrontierWAL` performs concurrent appends to both Redis Streams (`xadd`) and a local Append-Only File (AOF) (`local_wal_{run_id}.aof`).
- **CRC64 Integrity Checks**: Every log entry payload is stamped with a precomputed CRC64 checksum (with standard pure-Python lookup-table fallback) for rolling data integrity.
- **Fault-Tolerant Replica Recovery**: During `recover_deltas()`, corrupted entries are detected via CRC64 mismatch. If corruption is found in Redis, the system automatically falls back to reading the local AOF replica (and vice versa), maintaining consistent and clean state transitions.

## Process Pool ResourceWatchdog & Binary IPC

The worker execution pool has been upgraded for maximum resilience:
- **ResourceWatchdog**: A background monitoring loop periodically tracks pooled worker processes' RSS memory footprint and CPU utilization via `psutil`. Rogue workers exceeding limits (e.g. 512MB) are gracefully terminated and replaced.
- **Binary Zero-Disk IPC**: In addition to text line-oriented pipes, `execute_task_binary()` supports length-prefixed, `zstandard` (zstd)-compressed, `cloudpickle`-serialized object transfers over standard streams to seamlessly support complex structures.

## Bounded Compaction State Store

To enforce compaction during persistence:
- **BoundedCompactionStateStore**: Implements the `CheckpointStore` protocol, wrapping any backend.
- It transparently intercepts `write` cycles, executes CRDT compaction on the state payload within the AIMD budget, and persists only the bounded representation to keep storage usage low.

## Migration Handshake

Actor migration now has a prepare/commit handoff:

1. Source actor receives `prepare_migration`, freezes mutating work, and returns a stable `ghost-actor-snapshot-v2` envelope with `migration_id`, `last_wal_id`, and `state_digest`.
2. Coordinator stores the packed actor state, records a prepared marker in `GhostMeshRegistry`, updates placement, and commits the marker.
3. The source actor is stopped only after the committed marker and actor snapshot are durable.
4. The target node rehydrates from registry state and clears both the actor state and migration marker.

If the source node dies after prepare but before commit, the registry still contains a prepared marker and snapshot digest. If the cluster restarts after commit but before target spawn, the target can rehydrate from the committed snapshot without asking the dead source actor.

## Process Pool Receipts

`FrontierProcessPool` records per-task receipts keyed by caller-provided `task_id` or a stable digest of tool and task input. Completed receipts return cached output on retry. Cleanup marks in-flight tasks as `interrupted`, making restart supervisors replay those tasks once instead of assuming success.

## Demonstrated Paths

- Cold-start: `FrontierWAL.recover_state()` restores the CRDT snapshot and replays post-cursor WAL entries.
- Warm-rejoin: actor `recover` deduplicates repeated WAL IDs and list payloads.
- Full-cluster restart: committed migration markers and packed actor snapshots survive until the target clears them after rehydration.

## Test Evidence

Comprehensive tests in `tests/test_recovery_subsystem_upgrades.py` validate all new mechanics under realistic and corrupted scenarios, including binary IPC echo testing, budget tuning, CRC integrity fallbacks, and bounded store pruning. All unit and integration test suites run cleanly.
