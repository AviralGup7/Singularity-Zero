# Ghost-Actor Mesh & Frontier State Recovery Architecture

This document describes the state recovery contracts, CRDT snapshot serialization protocols, WAL journal replay mechanisms, and compaction budgeting implemented in the Cyber Security Test Pipeline.

---

## 💾 Recovery Contract & State Durability

The frontier state recovery path operates under a deterministic causal model:
1. **Checkpoint Snapshot**: Resumed actors and stages start from the latest complete CRDT state snapshot.
2. **Journal Replay**: Only WAL journal entries timestamped *after* the snapshot cursor are replayed.
3. **Idempotent Merge**: Every replayed transaction delta carries its unique `_wal_id` into `NeuralState`, ensuring that duplicate stream deliveries or repeated recovery messages are deduplicated and merged conflict-free without corruption.

---

## 📜 Snapshot Protocol & Envelope Format

`NeuralState.to_crdt_snapshot()` generates an immutable CRDT snapshot encapsulating:
- **State Envelope**: Target hostnames, endpoints, parameters, discovered findings, applied WAL identifiers (`applied_wal_ids`), and the Hybrid Logical Clock (HLC) timestamp.
- **AIMD Compaction Budget**: Retains dynamic compaction parameters (`budget_ms`, `min_budget_ms`, `max_budget_ms`, `target_elapsed_ms`) across reboots to prevent runtime compaction budget reset cycles.
- **Dynamic Logic Serialization**: Serializes custom stage handler definitions via `cloudpickle` and MessagePack, enabling seamless process and node rehydration.

---

## ⚡ CRDT Compaction Gating & Radix Sort

To prevent tombstone buildup and memory bloat over high-volume scans:
- **AIMD Compaction Budgeting**: `CRDTCompactionBudget` dynamically adjusts tombstone pruning budgets (in milliseconds) based on observed compaction latencies.
- **Optimized Radix Sort**: An $O(N)$ Least Significant Digit (LSD) radix sort is implemented for rapid timestamp sorting during compaction passes, backed by a robust pure-Python algorithm to ensure zero-downtime execution.
- **Compaction Gating**: `compact_state()` transparently gates tombstone pruning under the AIMD budget, keeping pipeline stages responsive.

---

## 🛡️ WAL Dual-Commit & CRC64 Integrity

- **Dual-Commit Protocol**: `FrontierWAL` performs concurrent appends to both Redis Streams (`xadd`) and local Append-Only Files (AOF).
- **Physical Disk Durability**: Local AOF commits execute explicit buffer flushes (`f.flush()`) and OS physical commits (`os.fsync()`), preventing corruption during hardware power interruptions.
- **CRC64 Checksums**: Every journal entry payload is verified via rolling CRC64 checksums. If corruption is detected in the Redis stream, the orchestrator automatically falls back to the local AOF replica (and vice versa).

---

## 🚀 Smart Cache Routing via Probabilistic Bloom Filters

- **Pre-Lookup Filter**: On cache read operations (`get` and `exists`), the cache manager first queries the probabilistic Bloom filter.
- **Zero-Latency Miss**: If a key is absent from the Bloom filter, the read immediately terminates as a cache miss, bypassing slower L2 (SQLite/Redis) and L3 (File) database lookups.
- **Auto-Population**: On cache writes, keys are automatically inserted into the Bloom filter to prevent subsequent routing false negatives.
