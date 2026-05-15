# Project: Singularity-Zero Architecture

This document defines the high-resilience, distributed execution model of the Cyber Security Test Pipeline. The system operates as a **Ghost-Actor Mesh**—a self-organizing, hardware-accelerated autonomous entity designed for infinite scale and zero silent failures.

---

## 🏗️ Core Principles: 'Singularity-Zero'

### 1. The 'Ghost' Execution Plane (Actor-Mesh)
- **Location-Transparent Actors**: Tasks are encapsulated as stateful Actors (via `pykka`). If a node experiences heavy load, actors can serialize their state and migrate to colder nodes mid-execution without dropping tasks.
- **Distributed Consensus & Sharding**: The mesh uses an authenticated SWIM-based Gossip protocol (HMAC-SHA256). A deterministic Bully algorithm elects shard leaders, and targets are distributed using Consistent Hashing.
- **CRDT State Engine**: All critical pipeline data (subdomains, URLs, findings) are stored in Conflict-free Replicated Data Types using **Vector-Clocked LWW-Sets**. Every state update perfectly preserves causality.
- **Durable Ledger (WAL)**: All state transitions are committed to a Redis-backed Write-Ahead Log *before* being merged into the context, surviving total cluster power loss.

### 2. Cognitive-Logic Analysis
- **Differential Logic Prober**: A high-speed State-Machine Fuzzer that compares endpoint responses across different authentication contexts using Levenshtein distance, automatically detecting IDOR and BAC vulnerabilities.
- **Lateral Movement Graph**: Integrates the `Kuzu` Graph Database to link subdomains, URLs, and findings into Attack Chains, predicting multi-hop exploitation paths (Kill-Chains).
- **Semantic Intelligence**: Finding deduplication uses vector-space Cosine Similarity via NumPy to group functionally identical security signals, bypassing rigid regex constraints.
- **Neural-Score Engine**: Calculates the Composite Severity Index (CSI) using multi-factor weighting (CVSS, Confidence, Exploitability, and Mesh Consensus).

### 3. Stealth & Anti-Forensics
- **Polymorphic Chameleon**: A real-time evasion engine that mutates request characteristics (header ordering, casing, JA3-simulation, temporal jitter) on every call, rendering the mesh invisible to behavioral WAFs.
- **Ghost-VFS (Volatile Virtual File System)**: An anti-forensic, RAM-only storage plane using AES-256-GCM. Artifacts never touch the physical disk and are permanently purged upon power-off or self-destruction.
- **Cyber Vault**: Target secrets and API keys are stored in a PBKDF2/AES-GCM secured vault, decrypted strictly in volatile memory.

### 4. Hardware Acceleration
- **SIMD Processing**: URL filtering and string analysis are offloaded to vectorized NumPy routines, enabling the processing of millions of URLs in milliseconds.
- **Binary Marshalling**: Zero-copy state transfers across the mesh utilizing `msgpack` for maximum network throughput.
- **Probabilistic Bloom Mesh**: Cluster-wide URL membership testing leverages MurmurHash3-backed Neural Bloom Filters, saving gigabytes of shared RAM.
- **Bloom Reconciliation Plane**: Nodes publish MessagePack Bloom snapshots over Redis pub/sub on `BLOOM_SYNC_INTERVAL_SEC`; vector clocks reject stale snapshots and compatible filters merge by packed-bit OR.
- **WASM Sandboxing**: Untrusted third-party scanners execute within a hardware-isolated WebAssembly runtime (`wasmtime`), preventing host kernel access.

---

## 🖥️ UI / UX Synchronization
The dashboard acts as a **Real-Time Mesh Command Center**:
- **Action Buffer Engine**: Employs a 100ms micro-batching reducer to prevent UI flicker and race conditions during massive telemetry bursts.
- **High-Performance Virtualization**: Uses `react-virtuoso` to render 100,000+ log lines and findings at a steady 60 FPS.
- **Off-Main-Thread Processing**: Heavy filtering and sorting of findings execute via Web Workers.
- **Zod Contract Guards**: Strict schema validation at the API boundary ensures silent schema drift is instantly caught.
- **Instanced 3D Rendering**: The Security Cockpit utilizes `THREE.InstancedMesh` and GPGPU layouts to render 50,000+ nodes in a single draw call.
- **Bloom Mesh Health Tile**: The dashboard polls `/api/bloom/health` for per-node memory, element count, false-positive probability, saturation history, and admin-triggered reconciliation.
