# Codebase Map & Module Directory

This document maps the project structure and core technologies of the Singularity-Zero architecture.

---

## 📂 Directory Structure

```text
src/
├── core/               # Shared contracts, frontier engines, utilities
│   ├── contracts/    # Immutable data models and StageInput definitions
│   ├── frontier/     # 🚀 Singularity-Zero core systems
│   │   ├── _state_cython.c      # Compiled Cython radix-sort extension (optional fast-path)
│   │   ├── _state_cython.pyx    # Cython source: high-speed radix sort for CRDT compaction
│   │   ├── bloom.py             # MurmurHash3 probabilistic filters
│   │   ├── bloom_mesh.py        # Neural Bloom Mesh: cluster-wide OR-merge of packed-bit snapshots
│   │   ├── chameleon.py         # Polymorphic WAF evasion engine
│   │   ├── chameleon_evasion.py # HMM-based evasion state machine, JA3 fingerprinting, timing permutation
│   │   ├── ghost_actor.py       # Pykka-based migratory actors
│   │   ├── ghost_vfs.py         # RAM-only anti-forensic storage with temporal AES-GCM key rotation
│   │   ├── marshaller.py        # MessagePack zero-copy serialization
│   │   ├── mesh_limiter.py      # Mesh message-rate limiter
│   │   ├── plugins/             # Dynamic plugin registry for frontier extensions
│   │   ├── proc_pool.py         # Worker-process resource pool
│   │   ├── ring_bus.py          # Inter-node broadcast ring bus
│   │   ├── state.py             # CRDT Vector-Clock / LWW-Sets / NeuralState
│   │   ├── tracing_manager.py   # Distributed tracing collector + exporter
│   │   ├── vault.py             # PBKDF2-600k-AES-256-GCM encrypted credential vault
│   │   ├── waf_patterns.py      # WAF fingerprint and evasion signature catalogue
│   │   ├── wal.py               # Redis-backed Write-Ahead Log (dual-commit: Redis Stream + local AOF)
│   │   └── wasm.py              # WebAssembly runtime isolation
│   └── utils/        # Lower-level utilities
│       ├── http_pool.py                  # HTTP connection pooling
│       ├── param_types.py                # Typed parameter descriptors
│       ├── safe_errors.py                # Safe error-stride generation
│       ├── shared.py                     # Shared helpers
│       ├── stderr_classification.py      # CLI-stderr classifier
│       ├── streaming.py                  # Streaming helpers
│       ├── timezones.py                  # TZ normalization
│       └── url_validation.py             # URL format validation
│
├── infrastructure/   # Platform & cross-cutting services
│   ├── cache/              # Redis, SQLite, and Distributed Lock logic
│   ├── mesh/               # 🕸️ P2P Distributed Systems
│   │   ├── balancer.py      # Multi-objective task bidding (NumPy Suitability Score)
│   │   ├── bidder.py        # Bidder registration and management
│   │   ├── consensus.py     # Deterministic leader election
│   │   ├── gossip.py        # Authenticated SWIM-based node discovery
│   │   ├── sharding.py      # Consistent-hashing target allocation
│   │   └── sync.py          # Node-state synchronization
│   ├── execution_engine/   # Concurrent task execution and load balancing
│   │   ├── concurrent_executor.py # Asyncio worker-pool fan-out
│   │   ├── config.py              # Execution engine configuration
│   │   ├── load_balancer.py       # Resource-aware task distributor
│   │   ├── models.py              # Task/result data models
│   │   ├── resource_pool.py       # Worker resource pool
│   │   ├── _scheduler.py          # Core scheduler loop
│   │   └── _task_runner.py        # Single-task execution wrapper
│   ├── queue/              # Redis-backed job queue and worker client
│   ├── scheduling/         # Resource-aware scheduling policies
│   ├── checkpoint/         # Distributed checkpoint persistence
│   ├── notifications/      # Email, Slack, and Webhook notification sinks
│   ├── observability/      # Structured logging, metrics, health checks, tracing
│   │   ├── alerts/             # Alert-channel manager
│   │   ├── metrics.py          # Prometheus integration
│   │   ├── structured_logging.py # JSON-structured log emission
│   │   ├── health_checks.py    # Dependency health probes
│   │   └── tracing/            # OpenTelemetry-compatible tracing
│   └── security/           # Auth, encryption, CORS, rate limiting, input validation
│
├── learning/           # Closed-loop feedback engine and FP-pattern repositories
│   ├── config/
│   ├── models/
│   ├── repositories/
│   ├── baseline_tracker.py
│   ├── feedback_loop.py
│   ├── finding_deduplicator.py
│   ├── fp_tracker.py
│   ├── integration.py
│   ├── metrics.py
│   ├── nuclei_tag_optimizer.py
│   ├── signal_quality.py
│   ├── telemetry_store.py
│   └── threshold_tuner.py
│
├── recon/              # Discovery (Subdomains, Live Hosts, URLs, JS metadata, archives)
├── analysis/           # 🧠 Cognitive-Logic Analysis
│   ├── intelligence/
│   │   ├── lateral_graph.py     # Kuzu Attack-Chain database
│   │   ├── differential_prober.py # IDOR/BAC State Fuzzer
│   │   ├── semantic_dedup.py    # Vector-space Cosine Similarity
│   │   └── neural_score.py      # Composite Severity Index (CSI)
│   ├── active/
│   ├── automation/
│   ├── behavior/
│   ├── checks/
│   ├── helpers/
│   ├── json/
│   ├── passive/
│   ├── plugins/
│   ├── plugin_runtime/
│   ├── response/
│   └── _core/
├── detection/          # Plugin registry and runtime dispatch
├── decision/           # Attack selection, prioritization, adaptive scheduling
├── execution/          # Vulnerability exploitation and validation
├── fuzzing/            # Payload generation
├── exploitation/       # Exploit models and validators
├── intelligence/       # ML, scoring, correlation, threat feeds
│   ├── campaigns/
│   ├── correlation/
│   ├── feeds/
│   ├── graph/
│   ├── ml/
│   └── scoring/
├── api_tests/           # Automated API vulnerability testing and fuzzing workflows
├── reporting/          # HTML PDF, VRT, triage, and compliance report generators
├── pipeline/           # DAG Orchestrator and service runners
├── websocket_server/   # WebSocket log streaming and real-time event relay
├── dashboard/          # FastAPI REST + 3D visualisation dashboard
├── cli.py              # Unified high-performance terminal engine
└── __init__.py
```

---

## 🧬 Frontier Tech Stack
The pipeline relies on highly optimized C/C++ extensions to bypass standard Python limits:

- **Infrastructure**: `pykka` (Actor Model), `redis` (Pub/Sub & Streams).
- **Hardware Acceleration**: `numpy` (SIMD Vectorization), `mmh3` (Fast Hashing), `msgpack` (Binary Marshalling).
- **Intelligence**: `kuzu` (Graph Database), `diff-match-patch` (Differential Analysis).
- **Security**: `cryptography` (AES-GCM, PBKDF2), `wasmtime` (Sandbox Isolation).
- **UI/UX**: `React 19.2.4`, `Three.js` (InstancedMesh), `framer-motion`, `react-virtuoso` (1M+ row virtualization), `zod` (Contract Validation), `radix-ui` (Accessible primitives), `lucide-react` (Icons).

---

## 📐 Architecture Rules
- **No In-Place Mutation**: Stages must emit `state_delta` dicts; the orchestrator merges via `NeuralState` CRDTs.
- **Strict Type Erasure**: All internal service boundaries must be wrapped with `@beartype`.
- **Zero-Trust Storage**: Assume the disk is compromised. Use `GhostVFS` for highly sensitive artifacts.
