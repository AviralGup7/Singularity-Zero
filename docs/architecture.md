# Project: Singularity-Zero Architecture

This document defines the high-resilience, distributed execution model of the Cyber Security Test Pipeline. The system operates as a **Ghost-Actor Mesh**—a self-organizing, hardware-accelerated autonomous entity designed for infinite scale and zero silent failures.

---

## 🏗️ Core Principles: 'Singularity-Zero'

### 1. The 'Ghost' Execution Plane (Actor-Mesh)
- **Location-Transparent Actors**: Tasks are encapsulated as stateful Actors (via `pykka`). If a node experiences heavy load, actors can serialize their state and migrate to colder nodes mid-execution without dropping tasks.
- **Distributed Consensus & Sharding**: The mesh uses an authenticated SWIM-based Gossip protocol (HMAC-SHA256). A deterministic Bully algorithm elects shard leaders, and targets are distributed using Consistent Hashing.
- **CRDT State Engine**: All critical pipeline data (subdomains, URLs, findings) are stored in Conflict-free Replicated Data Types using **Vector-Clocked LWW-Sets**. Every state update perfectly preserves causality.
- **Durable Ledger (WAL)**: All state transitions are committed to a Redis-backed Write-Ahead Log *before* being merged into the context, surviving total cluster power loss.
- **Tamper-Evident Audit Chain**: Administrative actions and sensitive API calls are recorded in a cryptographic audit ledger. Each entry contains an HMAC-SHA256 hash of the payload plus the previous entry's hash, creating an immutable chain-of-custody that can be verified via the dashboard.
- **Mesh-wide Intelligence Sync**: Employs a Redis-backed Pub/Sub channel (`mesh.learning.fp_patterns`) to instantly propagate analyst-flagged False Positives across the entire cluster. This ensures that a single triage event on one node auto-suppresses redundant findings cluster-wide.
- **Temporal Key Rotation & Hardening (Ghost-VFS)**: To minimize the exposure window of anti-forensic scan artifacts, Ghost-VFS automatically rotates its AES-GCM encryption keys every 4 hours. All RAM-stored data is re-encrypted on the fly. Rotation uses a pre-decryption validation phase and safe rollbacks to ensure zero data loss on failure, while derived and session keys are stored as mutable `bytearray` objects and zeroed out directly in RAM using `secure_wipe` after usage.

### 2. Cognitive-Logic Analysis
- **Differential Logic Prober**: A high-speed State-Machine Fuzzer that compares endpoint responses across different authentication contexts using Levenshtein distance, automatically detecting IDOR and BAC vulnerabilities.
- **Lateral Movement Graph**: Integrates the `Kuzu` Graph Database to link subdomains, URLs, and findings into Attack Chains, predicting multi-hop exploitation paths (Kill-Chains).
- **Semantic Intelligence**: Finding deduplication uses vector-space Cosine Similarity via NumPy to group functionally identical security signals, bypassing rigid regex constraints.
- **Cognitive-Logic Flow Probing**: Automatically discovers multi-request sequences (e.g., checkout flows) and models them as state transitions. The engine attempts to "break" these transitions by injecting out-of-order requests or manipulating state-dependent tokens (IDs, UUIDs), detecting high-level business logic flaws that atomic scanners miss.
- **Hardware-Isolated WASM Validation**: The **AEVE** engine executes proof-of-concept payloads within restricted WASM sandboxes (`wasmtime`). This provides hardware-level memory and CPU isolation, ensuring that even zero-day PoC logic cannot compromise the pipeline nodes while transitioning finding status from 'Candidate' to 'Verified TP'.
- **XGBoost & Active Learning Severity Engine**: Replaces traditional static scoring models with an industrial-grade **XGBoost and scikit-learn** machine learning pipeline (`XGBoostSeverityPipeline`). The pipeline vectorizes high-dimensional categorical features (vulnerability category, target host, parameter types, module names) using a constant-space `FeatureHasher` (128 slots). A thread-safe `ModelVersionRegistry` manages active model versions, telemetry health checks, and autonomous rollbacks, while the `ActiveLearningController` continuously extracts feedback and outcome signals from the telemetry database to trigger live retraining loops in post-scan hooks. Incorporates high-fidelity, pure-NumPy Logistic Regression fallbacks to ensure zero-downtime inference in environments without compiled binary packages.


### 3. Stealth & Anti-Forensics
- **Polymorphic Chameleon**: A real-time evasion engine that mutates request characteristics (header ordering, casing, noise headers) and timing behavior. Employs a Hidden Markov Model (HMM) to transition between states (undetected, suspected, blocked, evading) based on response behavior, dynamically adapting JA3 TLS browser fingerprints and injecting human-like exponential timing delays.
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
- **Interactive Request Replay**: Supports real-time "Replay with Diff" for finding verification. Enables analysts to modify headers, auth-modes, and payloads with side-by-side behavioral change detection.
- **Finding Intelligence**: Integrated collaborative notes and threaded analyst commentary for each security finding, synced via SSE.
- **Bloom Mesh Health Tile**: The dashboard polls `/api/bloom/health` for per-node memory, element count, false-positive probability, saturation history, and admin-triggered reconciliation.
