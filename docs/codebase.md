# Codebase Map & Module Directory

This document maps the project structure and core technologies of the Singularity-Zero architecture.

---

## 📂 Directory Structure

```text
src/
├── core/
│   ├── contracts/    # Immutable data models and StageInput definitions
│   ├── frontier/     # 🚀 Singularity-Zero core systems
│   │   ├── state.py       # CRDT Vector-Clock LWW-Sets
│   │   ├── wal.py         # Redis-backed Write-Ahead Log
│   │   ├── ghost_actor.py # Pykka-based migratory actors
│   │   ├── ghost_vfs.py   # RAM-only anti-forensic storage
│   │   ├── chameleon.py   # Polymorphic WAF evasion engine
│   │   ├── bloom.py       # MurmurHash3 probabilistic filters
│   │   ├── marshaller.py  # MessagePack zero-copy serialization
│   │   └── wasm.py        # WebAssembly runtime isolation
│   └── utils/
├── infrastructure/
│   ├── cache/        # Redis, SQLite, and Distributed Lock logic
│   ├── mesh/         # 🕸️ P2P Distributed Systems
│   │   ├── gossip.py      # Authenticated SWIM-based node discovery
│   │   ├── consensus.py   # Deterministic leader election
│   │   ├── sharding.py    # Consistent hashing target allocation
│   │   └── balancer.py    # Multi-objective task bidding
├── recon/            # Discovery (Subdomains, Live Hosts, URLs)
├── analysis/         # 🧠 Cognitive-Logic Analysis
│   ├── intelligence/
│   │   ├── lateral_graph.py     # Kuzu Attack-Chain database
│   │   ├── differential_prober.py # IDOR/BAC State Fuzzer
│   │   ├── semantic_dedup.py    # Vector-space Cosine Similarity
│   │   └── neural_score.py      # Composite Severity Index (CSI)
├── execution/        # Vulnerability exploitation and validation
├── pipeline/         # DAG Orchestrator and service runners
└── cli.py            # Unified high-performance terminal engine
```

---

## 🧬 Frontier Tech Stack
The pipeline relies on highly optimized C/C++ extensions to bypass standard Python limits:

- **Distributed Systems**: `pykka` (Actor Model), `redis` (Pub/Sub & Streams).
- **Hardware Acceleration**: `numpy` (SIMD Vectorization), `mmh3` (Fast Hashing), `msgpack` (Binary Marshalling).
- **Intelligence**: `kuzu` (Graph Database), `diff-match-patch` (Differential Analysis).
- **Security**: `cryptography` (AES-GCM, PBKDF2), `wasmtime` (Sandbox Isolation).
- **UI/UX**: `React 18`, `Three.js` (InstancedMesh), `framer-motion`, `react-virtuoso` (1M+ row virtualization), `zod` (Contract Validation).

---

## 📐 Architecture Rules
- **No In-Place Mutation**: Stages must emit `state_delta` dicts; the orchestrator merges via `NeuralState` CRDTs.
- **Strict Type Erasure**: All internal service boundaries must be wrapped with `@beartype`.
- **Zero-Trust Storage**: Assume the disk is compromised. Use `GhostVFS` for highly sensitive artifacts.
