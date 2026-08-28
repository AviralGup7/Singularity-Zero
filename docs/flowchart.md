# Flowchart Atlas

Visual graphs of the living docs under `docs/`. Charts are the map; the linked markdown files remain the specification.

**One file. Merged when overlapping.** Similar, nested, or part-of-each-other flows share a single survivor chart. Retired ids stay as headings that point at the survivor — they are not rewritten away and their ids are never reused.

---

## 0. Maintenance Contract & Snapshot Semantics

> **The Flowchart Atlas is the living snapshot of canonical architectural truth at revision N.**
>
> | Principle | Policy & Rule |
> |---|---|
> | **Canonical IDs** | `F-001` … `F-045` are stable architectural identifiers (15 active survivor charts, 31 retired pointers). |
> | **Retired Pointer Preservation** | Retired IDs are preserved exclusively in the Retired Chart Registry to resolve external identifier references. |
> | **Graph as Knowledge** | All relationships, authority levels, operational predicates, and negative constraints are encoded directly as graph edges and node attributes. |
> | **Explicit Edge Topology Law** | **Never assume "inside the same subgraph" means connected. Never assume "close together" means connected. Never use a subgraph as an architectural endpoint. Every important relationship gets its own explicit edge.** The layout engine is allowed to rearrange nodes, but it is not allowed to invent edges. |
> | **Render Engine & Parser Law** | **1. Single-Level Subgraphs Only**: Never nest subgraphs (`subgraph` inside `subgraph`). Dagre compound cluster collisions cause edge detachment and scattered layout.<br/>**2. ASCII Label Safety**: Avoid multi-byte unicode arrows (`↔`, `→`) in node labels or edge text; use ASCII `<->`, `->` to prevent parser failures.<br/>**3. KaTeX Underscore Escaping**: In math formulas, always escape literal underscores (`\_`) in `\text{...}` to prevent subscript `EOF` syntax errors.<br/>**4. Closed Code Fences**: Every diagram must start with ```` ```mermaid ```` followed by `flowchart TD/LR` and terminate with ```` ``` ````. |
> | **History in Git** | Historical evolution, audit logs, and document diffs belong to the Git database, not inside the AI knowledge graph. |
>
> How to modify this atlas:
> 1. Locate the active chart ID (`F-001` …).
> 2. Patch the relevant graph, decision matrix, or registry directly.
> 3. Update the Atlas Index entry.

---

## Legend & Status Vocabulary

Every graph in this atlas adheres to a standardized, machine-verifiable visual taxonomy. Node colors and border strokes are not decorative—they encode the runtime maturity, deployment reality, and safety boundaries of every component.

### Color Architecture & Meaning

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │ 🟢 Emerald Green (#10b981) │ Live, fully implemented production code  │
  ├─────────────────────────────┼──────────────────────────────────────────┤
  │ 🔵 Cyan / Blue (#0ea5e9)   │ Single-node / in-process mode (Quorum-1) │
  ├─────────────────────────────┼──────────────────────────────────────────┤
  │ ⚪ Slate Gray (#64748b)    │ Imported utility / library / test mock   │
  ├─────────────────────────────┼──────────────────────────────────────────┤
  │ 🟣 Indigo (#818cf8)         │ Formal specification plane / target arch │
  ├─────────────────────────────┼──────────────────────────────────────────┤
  │ 🔘 Zinc Muted (#71717a)     │ Vacuous / rehydration pass (empty run)   │
  ├─────────────────────────────┼──────────────────────────────────────────┤
  │ 🔴 Crimson Red (#ef4444)    │ Fail-closed boundary / forbidden action  │
  └─────────────────────────────┴──────────────────────────────────────────┘
```

* **Live Execution Plane (🟢 Emerald / `:::impl`)**: Indicates active runtime modules in `src/`. These components are covered by unit/integration tests and run in active CLI scans and daemon workers.
* **In-Process Quorum-1 Plane (🔵 Cyan / `:::singleNode`)**: Denotes distributed protocols (such as Raft consensus and mesh state) currently running in local single-node mode without active cross-host clustering.
* **Utility & Shared Layer (⚪ Slate / `:::library`)**: Represents pure functions, algorithms, in-memory test mocks (`MemoryJournal`), or imported helper packages rather than long-running daemons.
* **Specification Target Plane (🟣 Indigo / `:::specOnly`)**: Represents formal multi-node distributed designs (e.g. cross-region replication relays, multi-host ghost migrations) defined in contracts but not yet instantiated as active daemons.
* **Vacuous Pass Plane (🔘 Zinc / `:::vacuous`)**: Identifies intermediate state recovery checks or replay steps that are structurally required by the FSM but evaluate to zero mutations during normal clean runs.
* **Safety & Security Boundary (🔴 Crimson / `:::forbidden`)**: Explicitly marks illegal state transitions, network egress violations, and fail-closed gates that trigger aborts or budget compensation.

---

### Node Status Classes (`classDef`)

| ClassDef | Name | Color | Border Stroke | Definition & Runtime Scope |
|---|---|---|---|---|
| `:::impl` | **Fully Implemented** | Dark Slate (`#1f2937`) | **Emerald Green** (`#10b981`, 2px solid) | Live production code in `src/` |
| `:::singleNode` | **Single-Node Quorum-1** | Dark Blue (`#1e293b`) | **Sky Blue** (`#0ea5e9`, 1px dashed) | Operating in-process or local cluster mode |
| `:::library` | **Library Component** | Slate (`#334155`) | **Slate Gray** (`#64748b`, 1px solid) | Imported as utility or test mock |
| `:::specOnly` | **Specification Plane** | Indigo Dark (`#1e1b4b`) | **Indigo Accent** (`#818cf8`, 1px dashed) | Formal target architecture |
| `:::vacuous` | **Vacuous State** | Zinc Dark (`#27272a`) | **Zinc Gray** (`#71717a`, 1px solid) | Normal empty check / rehydration pass |
| `:::forbidden` | **Forbidden / Fail-Closed** | Crimson Dark (`#450a0a`) | **Bright Red** (`#ef4444`, 2px solid) | Explicitly illegal flow rejected by gates |

### Edge Semantics & Grammar

| Syntax | Category | Semantic Meaning & Runtime Role |
|---|---|---|
| `A --> B` | **Structural / Reference** | Documentation link, static hierarchy, CI prerequisite, downstream consumer |
| `A ==> B` | **Hot Path / Execution** | Synchronous control flow, DAG scheduling dispatch, hot worker execution |
| `A -->|data| B` | **Dataflow & Ingestion** | Findings, URLs, payloads, context artifact ingestion |
| `A -->|replicate| B` | **Replication** | Network journal sync, cross-region peer relay |
| `A -->|state| B` | **State Transition** | Deterministic CAS lifecycle progression (e.g. `PENDING` $\rightarrow$ `RUNNING`) |
| `A -->|durable| B` | **Durable Side Effect** | Synchronous WAL commit, Outbox append, fsync flush |
| `A -.->|when: cond| B` | **Scheduling Gate** | Runtime predicate evaluation (e.g. `OutputNonEmpty`) |
| `A -.->|refuse/guard| B` | **Invariant Refusal** | Fail-closed security boundary, egress guard, illegal flow rejection |
| `PORT_FNNN[["..."]]` | **Interface Port** | Typed boundary connector between partitioned charts |

### Typed Authority Taxonomy

The term "authority" is strictly typed across this specification to avoid semantic overloading. All 37 invariants (I1–I37) are exhaustively governed:

| Typed Authority | Scope & Plane | Authoritative Entity | Governed Invariants |
|---|---|---|---|
| **`GovernanceAuthority`** | Partition Plane (Raft L0–L1, `P-0000`) | `ReplicatedPartitionLog`, `PolicyGovernanceGate`, `RaftFSM` | I1, I2, I3, I4, I8, I9, I10, I11 (Joint Prerequisite), I13, I18, I20, I22, I25 |
| **`BudgetAuthority`** | Partition Plane (`P-0000` L1 FSM / L3 Reconstructible View) | `GlobalBudgetAggregate`, `HuntBudget` | I5, I6, I7, I19, I21, I23, I26, I28 |
| **`DiscoveryAuthority`** | Frontier Scan Plane (CRDT view over journaled discovery) | `NeuralState` OR-Sets (`subdomains`, `urls`, `findings`), `CASStore` | I24, I27 |
| **`ExecutionAuthority`** | Runtime Control & Scope Sandbox | `ExecutionAuthorizer`, `ProcessSandbox` | I29, I30, I33 |
| **`PersistenceAuthority`** | Storage & Durability Engine (L0/L2) | `PartitionWAL` (CRC-64 fsync), `DurableOutboxLedger` | I11 (Joint Prerequisite), I12, I14, I15, I16, I31, I32 |
| **`RecoveryAuthority`** | Recovery & Regional Consensus Plane | `RecoveryManager`, `RecoveryProtocol`, `RegionModel`, `AuthorityTransfer` | I17, I34, I35, I36, I37 |
| **`PresentationAuthority`** | Ephemeral & Read Projections (L4–L5) | FastAPI, Zustand Stores, Telemetry Normalizer | — *(N/A: read-only projection; must not enforce any I1–I37; prohibited from mutating L0–L3)* |

---

## Atlas Index

Only active, non-merged charts appear here. Merged IDs are listed in the Retired Chart Registry with their survivor.

| Id | Chart | Source Specification & Symbols | Absorbed | Status |
|---|---|---|---|---|
| F-001 | Documentation portal map | [index.md](index.md), [getting-started.md](getting-started.md), [deployment.md](deployment.md) | — | Active |
| F-002 | System topology, regions & deployment | [architecture-overview.md](architecture-overview.md), [multi-region.md](multi-region.md), [deployment.md](deployment.md), `region_model.py` (I36), `authority_transfer.py` (I37), `launcher.py` | F-021, F-040 | Active |
| F-003 | Authority plane, Raft L0–L5 & security keys | [architecture.md](architecture.md), [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md), `replicated_log.py`, `receipt_crypto.py`, `schema_upcaster.py`, `state.py` | F-012, F-014, F-016, F-034, F-037, F-044 | Active |
| F-004 | Live scan path, execution DAG & egress sandbox | [architecture.md](architecture.md), [codebase.md](codebase.md), [commands.md](commands.md), `graph_builder.py`, `_run_execution.py`, `stage_admit.py`, `process_sandbox.py`, `egress_context.py`, `shared_sessions.py`, `dedup/` | F-005, F-010, F-013, F-015, F-017, F-029, F-035, F-036, F-042 | Active |
| F-006 | Leases, time & global budget | [architecture.md](architecture.md), [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md), `hunt_budget.py`, `lease_status.py` | F-011, F-038 | Active |
| F-007 | Application state machines & lifecycle coupling | `src/jobs/status.py`, `src/core/models/stage_status.py`, `src/core/contracts/finding_lifecycle.py`, `run_outcome.py` | F-008, F-027 | Active |
| F-009 | Resilience: breaker, QoS, PID & bulkhead | [architecture.md](architecture.md), [performance.md](performance.md), `src/resilience/`, `src/realtime/prioritized_broker.py`, `src/realtime/qos_admit.py` | F-024, F-030 | Active |
| F-018 | Failure decision tree, concurrency & I35 recovery | [FAILURE_MODES.md](FAILURE_MODES.md), `failure_model.py` (I34), `recovery_protocol.py` (I35), `recovery/manager.py`, `run_lock.py` | F-039 | Active |
| F-019 | Operator surface, multi-tenancy & telemetry | [frontend.md](frontend.md), [api-reference.md](api-reference.md), [OBSERVABILITY_CATALOG.md](OBSERVABILITY_CATALOG.md), `telemetry/normalizer.ts`, `middleware.py` | F-023, F-026, F-031, F-043 | Active |
| F-020 | Tests, CI shards & quality policy gates | [testing.md](testing.md), [ci-cd-integration.md](ci-cd-integration.md), `.github/workflows/ci.yml`, `run_outcome.py` | F-045 | Active |
| F-022 | Gap-analysis status | [GAP_ANALYSIS.md](GAP_ANALYSIS.md) | — | Active |
| F-025 | Non-authoritative planes, caches & multi-tier storage | [architecture/cache-unification.md](architecture/cache-unification.md), [environment-variables.md](environment-variables.md), `src/infrastructure/cache/`, `src/pipeline/unified_cache/`, facades `src/cache/`, `src/checkpoint/`, `src/frontier/` | F-028, F-032, F-041 | Active |
| F-033 | Global invariants I1–I37 enforcement & dependency graph | `invariant_graph.py`, `global_invariants.py`, `causal_identity.py`, `event_delivery.py` | — | Active |


---

## F-001 — Documentation portal map

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    Index["docs/index.md"] --> Arch["architecture.md"]
    Index --> Overview["architecture-overview.md"]
    Index --> Formal["FORMAL_COMMAND_SPECIFICATION.md"]
    Index --> Gaps["GAP_ANALYSIS.md"]
    Index --> Atlas["flowchart.md THIS FILE"]
    Index --> Code["codebase.md"]
    Index --> Cmds["commands.md"]
    Index --> Env["environment-variables.md"]
    Index --> Fail["FAILURE_MODES.md"]
    Index --> Obs["OBSERVABILITY_CATALOG.md"]
    Index --> Test["testing.md"]
    Index --> Front["frontend.md"]
    Index --> Multi["multi-region.md"]
    Index --> Perf["performance.md"]
    Index --> Gloss["glossary.md"]
    Index --> ApiDoc["api-reference.md"]
    Index --> Start["getting-started.md"]
    Index --> Deploy["deployment.md"]
    Index --> CICD["ci-cd-integration.md"]
    Index --> Plugins["dynamic-plugins.md"]
    Index --> Trouble["troubleshooting.md"]
    Index --> PagesOver["frontend_pages_overview.md"]
    Index --> Sec["../SECURITY.md"]
    Arch --> ExecReq["architecture/execution-request-contract.md"]
    Arch --> CacheDoc["architecture/cache-unification.md"]
    Arch --> Consolidation["architecture/code-consolidation.md"]
```

---

## F-002 — System topology, regions & deployment

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph Topology["Spatial Deployment & Multi-Region Topology (launcher.py, multi-region.md)"]
        Browser["React 19 Dashboard (:5173 / :8000)"]:::impl <-->|"REST / WebSocket"| API["FastAPI Dashboard Server (:8000)"]:::impl
        API <-->|"Redis Job Queue & Streams<br/>(Circuit Breaker + Local SQLite Spool Fallback)"| Worker["Pipeline Background Worker Daemon"]:::impl
        Worker ==>|"subproc spawn"| Tools["Security Tool Subprocesses (nuclei, httpx, etc.)"]:::impl
        Worker -->|"metrics push"| PromSink["Prometheus / Grafana (:9090)"]:::impl
        
        Worker ==> Orch["Pipeline Orchestrator"]:::impl
        Orch ==> Engines["Recon / Analysis / Fuzz / Exploit"]:::impl
        Orch -->|data| State["WAL / CRDT / Cache / Mesh"]:::impl
        Engines -->|data| Sinks["Learning + Reporting"]:::impl
        State -->|data| Sinks
    end

    subgraph MultiRegionAuthority["Multi-Region Single-Writer & I37 Authority Transfer (I36, I37)"]
        A["Region A<br/>OWNED (Active Writer)"]:::impl -->|"initiate_transfer(Epoch E)"| F["FENCED<br/>(Zero-Writer; Mutations Rejected)"]:::impl
        F -->|"activate_ownership(Epoch E+1)"| B["Region B<br/>OWNED (Active Writer)"]:::impl
        F -->|"abort_transfer / timeout"| A_Abort["Region A<br/>OWNED (Epoch E+1 Bumped)"]:::impl
        
        F -.->|"refuse: stale epoch/token"| Rej1["Refuse: Stale Epoch / Token"]:::forbidden
        F -.->|"refuse: mutation while fenced"| Rej2["Refuse: Partition FENCED"]:::forbidden
        
        A_Abort -.->|"delayed activate rejected: activation_token_mismatch"| RejDelayed["Refuse: Stale Activation Token"]:::forbidden
        
        A ==>|"authoritative write"| OA["P-0000 Leader PartitionWAL (Commands & Budget)"]:::impl
        A ==>|"authoritative write"| JA["FrontierWAL Journal (Scan Discovery)"]:::impl
        JA -->|"WALReplicationRelay (Journal Only I36)"| JB["Region B FrontierWAL Replica (Monotonic Read)"]:::specOnly
        B -.->|"refuse: foreign mutation rejected"| RejB["I36/I37 Refuse Foreign Writer"]:::forbidden
        
        GA["Gossip Node A1"]:::impl -.-|"SWIM UDP (AES-256-GCM Nonce 96-bit I24)"| GB["Gossip Node B1"]:::specOnly
        Consensus["MeshConsensus (Adaptive RTT Timeout 10x + Pre-Vote Guard)"]:::impl --> GA & GB
    end
```

---

## F-003 — Authority plane, Raft L0–L5 & security keys

### Bidirectional Schema Evolution & Key Hierarchy

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    OldPayload["Legacy Command / Payload (v1 / v2)"]:::impl -->|upcast (forward-compat)| Registry["SchemaMigrationRegistry (v1 <-> v2 <-> v3)"]:::impl
    NewPayload["Future / v3+ Payload"]:::impl -->|reverse-translate (reverse-compat)| Registry
    Registry -->|target new| Envelope["Output: Canonical Envelope (v3)"]:::impl
    Registry -->|target legacy / rolling upgrade| DowngradedEnvelope["Output: Downgraded Envelope + _unknown_fields bag"]:::impl
    MasterKey["AUTHORITY_SIGNING_KEY / APP_SECRET_KEY"]:::impl --> KeyRing["AuthorityKeyRing (Multi-Generation Overlap)"]:::impl
    KeyRing -->|"active (Gen N)"| Derive["HMAC Key Derivation"]:::impl
    KeyRing -->|"overlap (Gen N-1)"| OverlapVerify["Historical Verification Window (Zero Downtime)"]:::impl
    RotateCmd["Raft: RotateAuthorityKey Command"]:::impl -->|"ceremony"| KeyRing
    Derive --> ReceiptKey["CommandReceipt Key (key_generation bound)"]:::impl
    Derive --> MeshKey["MESH_SECRET (AES-256-GCM)"]:::impl
    Derive --> JWTKey["JWT Session Key"]:::impl
    MasterKey -.->|"Missing in Env (Pre-Raft Bootstrap Guard)"| Fallback["Refuse: Missing Master Secret FAILS_CLOSED"]:::forbidden
```

### Partition Plane, Raft Consensus & Non-Authoritative Strata (L0–L5)

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph AuthoritativeStrata["L0–L3: Authoritative Partition Plane (Raft & WAL)"]
        Tuner["Policy Governance Gate"]:::impl --> Promo["Promote / Rollback Policy"]:::impl
        Promo --> EnvelopeIn["Canonical Envelope (v3)"]:::impl
        EnvelopeIn --> Admit["Admission Clock-Skew Check I22 (+10s / -5s Monotonic Gate)"]:::impl
        Admit --> Log["ReplicatedPartitionLog"]:::impl
        
        %% L0: Multi-Node Raft Consensus
        Leader["Leader PartitionWAL (Group Commit 64 entries / 1ms configurable)"]:::impl
        F1["Follower PartitionWAL Replica (Group Commit)"]:::impl
        F2["Follower PartitionWAL Replica (Group Commit)"]:::impl
        Leader -->|"AppendEntries RPC"| F1 & F2
        F1 & F2 -->|"Majority Quorum ACKs (>= 2 of 3)"| Leader
        Leader --> Commit["Advance commitIndex & FSM Barrier"]:::impl

        Log --> Leader
        Commit ==> Apply["L1: FSM.Apply (Pure Deterministic Zero I/O)"]:::impl
        Apply --> StateHash["Deterministic State Hash (SHA-256)"]:::impl
        StateHash --> Receipt["HMAC-SHA256 CommandReceipt"]:::impl
        Apply ==> Intent["Pure OutboxIntent Emitted (Zero I/O)"]:::impl
        Intent -->|durable append| Outbox["L2: DurableOutboxLedger"]:::impl
        Outbox --> Proj["L3: Materialized Projections (GlobalBudgetAggregate P-0000)"]:::impl
        
        Outbox --> PORT_CRDT_BRIDGE[["PORT: DurableOutbox Settlement Bridge -> F-004 SettlementCoordinator"]]
        Outbox --> PORT_F019_BUS[["PORT: F-019 DurableOutbox EventBus Dispatch"]]
    end
    
    subgraph FrontierPlane["FRONTIER PLANE: Scan Discovery (CRDT View over Journaled Discovery)"]
        F_Targets["Target Subdomains & URLs"]:::impl
        F_Findings["Findings CRDT Bag (REPORTABLE)"]:::impl
        F_Candidates["Candidates CRDT Bag (Non-Reportable)"]:::impl
        F_Tombstones["Compaction Tombstones (Adaptive Gossip RTT x 3 Safety Factor TTL, Floor=300s)"]:::impl
        F_Targets -->|data| F_Findings
        F_Targets -->|data| F_Candidates
        F_Findings -->|"garbage-collect / retire"| F_Tombstones
        F_Candidates -->|"garbage-collect / retire"| F_Tombstones
    end
    
    subgraph ReadProjections["READ PROJECTIONS: Strictly Non-Authoritative Strata (L4–L5)"]
        Proj -->|materialize| Cache["L4: Caches & Telemetry (Prometheus localhost:9090 Default + mTLS Guard)"]:::impl
        Cache ==>|render| UI["L5: Presentation & Dashboard UI"]:::impl
        
        UI -.->|"FORBIDDEN: direct mutation rejected"| Log
        Cache -.->|"FORBIDDEN: caches cannot mutate WAL"| Log
    end
```

---

## F-004 — Live scan path, execution DAG & egress sandbox

```mermaid
flowchart TD

    %% ============================================================
    %% NODE CLASSES
    %% ============================================================

    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;
    classDef anchor fill:#111827,stroke:#94a3b8,stroke-width:2px,color:#fff;
    classDef property fill:#172554,stroke:#60a5fa,stroke-width:1px,color:#dbeafe;


    %% ============================================================
    %% GRAPH BUILDER
    %% DISCOVER -> VALIDATE -> COMPOSE -> VERIFY -> FREEZE
    %% ============================================================

    subgraph GraphBuilderPipeline["Dynamic Plugin & DAG Lifecycle"]

        BaseNodes["1. _BASE_NODES (19 Static Built-in Nodes)"]:::impl

        MergePlugins["2. COMPOSE: Deterministic Merge Plugins from StageRegistry"]:::impl

        ProfileOverride["3. Capability Profile (Tool Availability Probes)"]:::impl

        PruneTools["4. Prune Unavailable Tools (nuclei/semgrep binary check)"]:::impl

        DynamicJoin["5. _join_finding_producers (Bind finding producers to reporting)"]:::impl

        CycleCheck["6. VERIFY: Acyclic & Safety Check (I-GRAPH-01..08)"]:::impl

        Freeze["7. FREEZE: Immutable Graph (nodes=tuple) + GraphGenID"]:::impl

        FrozenGraph["Frozen Runtime Graph (Immutable Node / Dependency Set)"]:::anchor

        GraphGenID["GraphGenID (Canonical Frozen Graph Identity)"]:::property

        BaseNodes --> MergePlugins
        MergePlugins --> ProfileOverride
        ProfileOverride --> PruneTools
        PruneTools --> DynamicJoin
        DynamicJoin --> CycleCheck
        CycleCheck -->|"deterministic graph generation"| Freeze

        Freeze --> FrozenGraph
        FrozenGraph --> GraphGenID
    end


    %% ============================================================
    %% PROCESS BOOTSTRAP / RECOVERY / AUTHORITY
    %% ============================================================

    subgraph Init["Process Bootstrap & Authority Attachment"]

        CSTP["cstp CLI"]:::impl

        Launch["launch: Dashboard + Background Worker"]:::impl

        Scan["scan run: Runtime Pipeline"]:::impl

        Sys["system doctor / status / setup / cleanup"]:::impl

        Runtime["src.pipeline.runtime"]:::impl

        Bind["register_process_bindings"]:::impl

        Recover["RecoveryManager (I35 Snapshot + WAL Protocol)"]:::impl

        Verify["verify_checkpoint_against_fsm"]:::impl

        Auth["attach_pipeline_authority"]:::impl

        Stamp["ctx.budget_enforcer + authorizer"]:::impl

        CSTP --> Launch
        CSTP --> Scan
        CSTP --> Sys

        Launch --> Bind
        Scan --> Runtime
        Runtime --> Bind

        Bind --> Recover

        Recover -->|"verify state"| Verify
        Recover -->|"attach authority"| Auth

        Verify --> Auth

        Auth -->|"inject context"| Stamp
    end


    %% ============================================================
    %% FROZEN GRAPH / RUNTIME GRAPH / GENERATION VALIDATION
    %% ============================================================

    StageGraphRoot["RUNTIME STAGE_GRAPH (Frozen Executable Dependency Graph)"]:::anchor

    GraphGenGate["GraphGenID Validation Gate"]:::property

    GraphGenID -->|"generation identity"| GraphGenGate

    FrozenGraph -->|"frozen graph consumed at runtime"| StageGraphRoot

    GraphGenGate --> Req

    Stamp -->|"runtime authorizer binding"| Req

    Stamp --> Sub


    %% ============================================================
    %% SCHEDULER CONTROL MODEL
    %% ============================================================

    Scheduler["ActorScheduler Greedy Readiness Loop"]:::impl

    ReadinessRoot["READINESS / STAGE STATUS CONTROL MODEL"]:::anchor

    ReadinessEvaluation["Readiness Evaluation (needs + when gates)"]:::property

    StageGraphRoot -->|"evaluate graph dependencies"| ReadinessEvaluation

    ReadinessEvaluation -->|"readiness result"| Scheduler

    Scheduler -->|"control state / lifecycle evaluation"| ReadinessRoot


    %% ============================================================
    %% RUNTIME EXECUTABLE STAGE GRAPH
    %% ============================================================

    subgraph DAG["Runtime Executable STAGE_GRAPH (ActorScheduler Readiness & Gates)"]

        Sub["subdomains"]:::impl

        Takeover["subdomain_takeover"]:::impl

        LiveH["live_hosts [critical=true]"]:::impl

        WAF["waf"]:::impl

        Urls["urls"]:::impl

        ReconVal["recon_validation"]:::impl

        GitDiff["git_diff_crawl"]:::impl

        Params["parameters"]:::impl

        Rank["ranking"]:::impl

        Passive["passive_scan"]:::impl

        Active["active_scan"]:::impl

        Semgrep["semgrep"]:::impl

        Nuclei["nuclei"]:::impl

        Access["access_control"]:::impl

        Val["validation"]:::impl

        Intel["intelligence"]:::impl

        Threat["threat_modeling"]:::impl

        Report["reporting [JOIN_SINK]"]:::impl

        DynProducers["Dynamic Producers (sca_scan, container_scan, iac_scan, git_secret_scan)"]:::impl

        Sarif["sarif_export"]:::impl

        CiExp["ci_export"]:::impl

        Dedup["dedup_stage (Structural Parameterized Fingerprinting)"]:::impl


        %% Root of the frozen runtime graph
        StageGraphRoot --> Sub

        %% Main DAG
        Sub --> Takeover
        Sub --> LiveH

        LiveH --> WAF
        LiveH --> Urls

        Urls --> ReconVal
        Urls --> GitDiff
        Urls --> Params

        WAF --> Rank
        Params --> Rank
        Urls --> Rank

        Rank --> Passive
        LiveH --> Passive
        Urls --> Passive

        Passive --> Active
        Passive --> Semgrep
        Passive --> Nuclei

        Rank --> Access
        Passive --> Access

        %% Runtime scheduling gates
        LiveH -.->|"when: OutputNonEmpty('live_hosts')"| Active
        LiveH -.->|"when: OutputNonEmpty('live_hosts')"| Semgrep
        LiveH -.->|"when: OutputNonEmpty('live_hosts') and FlagSet('nuclei_available')"| Nuclei
        LiveH -.->|"when: OutputNonEmpty('live_hosts')"| Access

        %% Validation / intelligence
        Passive --> Val
        Active --> Val

        Passive --> Intel
        Active --> Intel
        Nuclei --> Intel
        Val --> Intel

        Intel --> Threat

        %% Join sink
        Intel --> Report
        Nuclei --> Report
        Access --> Report
        Threat --> Report
        Val --> Report
        Semgrep --> Report
        Passive --> Report
        Takeover --> Report

        DynProducers -->|"composition: _join_finding_producers"| Report

        %% Terminal outputs
        Report --> Sarif
        Report --> CiExp
        Report --> Dedup
    end


    %% ============================================================
    %% READINESS FSM
    %% ============================================================

    subgraph ReadinessFSM["Scheduler Readiness vs Persisted StageStatus"]

        P_PEND["PENDING (persisted)"]:::impl

        P_CAND["candidate ready (scheduler-local)"]:::impl

        P_DISP["dispatch actor"]:::impl

        P_RUN["RUNNING (persisted)"]:::impl

        P_COMP["COMPLETED (persisted)"]:::impl

        P_DEG["DEGRADED (persisted)"]:::impl

        P_FAIL["FAILED (persisted)"]:::impl

        P_DEF["deferred (scheduler-local control state)"]:::vacuous

        P_SKIP["SKIPPED_DISABLED [TERMINAL FOR RUN] (reason=condition_never_satisfied)"]:::impl

        P_SKIP_FAIL["SKIPPED_FAILED (persisted)"]:::impl

        DownstreamRun["downstream execution continues (non-critical)"]:::impl


        %% Scheduler enters / evaluates persisted state
        ReadinessRoot --> P_PEND

        %% Normal readiness lifecycle
        P_PEND -->|"_need_met all deps"| P_CAND

        P_CAND -->|"when.is_satisfied == True"| P_DISP

        P_DISP -->|"spawn execution"| P_RUN

        %% Terminal execution outcomes
        P_RUN -->|"success"| P_COMP
        P_RUN -->|"partial / degraded"| P_DEG
        P_RUN -->|"failure"| P_FAIL

        %% Scheduler-local control state
        P_CAND -.->|"when == False (control state)"| P_DEF

        P_DEF -.->|"tick retry"| P_CAND

        P_DEF -->|"scan drain"| P_SKIP

        %% Critical upstream failure
        P_PEND -->|"upstream_critical_failure"| P_SKIP_FAIL

        %% Failure propagation
        P_FAIL -->|"non-critical stage failure"| DownstreamRun

        P_FAIL -->|"critical stage failure (e.g. live_hosts)"| P_SKIP_FAIL
    end


    %% Explicit scheduler / readiness relations
    Scheduler -->|"evaluate persisted lifecycle"| P_PEND
    Scheduler -->|"dispatch actor"| P_DISP

    %% ============================================================
    %% READY STAGE -> EXECUTION REQUEST
    %% ============================================================

    Req["ExecutionRequest (ScopeGroupLock + Target RunLock)"]:::impl

    P_DISP -->|"ExecutionRequest for dispatched stage"| Req

    StageGraphRoot -->|"per ready node"| Req


    %% ============================================================
    %% EXECUTION GATE / AUTHORIZATION / EGRESS
    %% ============================================================

    subgraph Sandbox["Execution Gate & Universal Egress Enforcement (I29 / I30 / F-036)"]

        Budget["HuntBudget.reserve"]:::impl

        Rej["ScopeAuthorizationError (Skipped)"]:::forbidden

        Ticket["AuthorizedExecutionTicket I30 (ScopeToken + BudgetRes + Rev + CmdID + BlastRadius)"]:::impl

        Consume["ExecutionAuthorizer.consume (Atomic Lock & Nonce Check)"]:::impl

        InstallFilt["install_filter_from_scope -> egress_context ContextVar"]:::impl

        Guard["I29 Universal Egress Authority"]:::impl

        PORT_F006_RES[["PORT: F-006 ReserveGlobalBudget"]]


        Req -->|"1. request authorization"| Budget

        Budget -->|"Exhausted"| Rej
        Budget -->|"OK"| Ticket
        Budget --> PORT_F006_RES

        Ticket -->|"2. single-use consumption"| Consume

        Consume -->|"3. scope filter install"| InstallFilt

        InstallFilt -->|"4. universal egress guard"| Guard


        %% --- Application & Runtime Egress Layer ---
        HTTPX["httpx.Client (Application Hook)"]:::impl
        Requests["requests.Session (Application Hook)"]:::impl
        Shared["shared_sessions.py (Application Hook)"]:::impl
        Socket["socket.socket.connect (Socket Patch)"]:::impl
        Stream["asyncio.open_connection (Stream Patch)"]:::impl
        Browser["runtime_browser.py (Browser Guard)"]:::impl

        Guard -->|"hook"| HTTPX
        Guard -->|"hook"| Requests
        Guard -->|"hook"| Shared
        Guard -->|"patch"| Socket
        Guard -->|"patch"| Stream
        Guard -->|"guard"| Browser


        %% --- Kernel-Level Isolation Layer ---
        Subproc["ProcessSandbox (Kernel NetNS + Seccomp-BPF)"]:::specOnly

        Guard -->|"sandbox"| Subproc


        %% --- Execution Output Aggregation ---
        Out["StageOutput / ExploitClaim (Bounded 64KB CAS Merkle Root I27)"]:::impl

        HTTPX --> Out
        Requests --> Out
        Shared --> Out
        Socket --> Out
        Stream --> Out
        Browser --> Out
        Subproc --> Out


        %% --- Universal Egress Refusal & Compensation ---
        Viol["EgressViolationError (Out-of-Scope / IMDS Deny)"]:::forbidden
        KillSubproc["Kill Process & Drop Untrusted Claim"]:::forbidden
        SettleDrop["Settle DROPPED (No Finding)"]:::forbidden
        EgressCompensate["I28 Budget COMPENSATE"]:::impl

        Guard -.->|"refuse IMDS / out-of-scope"| Viol
        Viol --> KillSubproc
        KillSubproc --> SettleDrop
        SettleDrop --> EgressCompensate


        %% Standalone exploiter remains inside mandatory ticket path
        Exploit["Standalone SafeExploiter.execute"]:::impl

        Exploit -->|"Mandatory ScopeToken + Budget Reservation"| Ticket
    end


    %% ============================================================
    %% SETTLEMENT PIPELINE
    %% ============================================================

    subgraph SettlementPipeline["Settlement & Deduplication Pipeline (I28 / I31 / I32 / F-042)"]

        PORT_F003_SETTLE_BRIDGE[["PORT: F-003 DurableOutbox Settlement Bridge"]]

        Coord["SettlementCoordinator (5-Stage Claim Validation)"]:::impl

        Fingerprint["Structural Parameterized Fingerprint (tool|path|param|type|sig)"]:::impl

        Thaw["_to_mutable Record Format"]:::impl

        WAL["StateAuthority.append SettlementIntent"]:::impl

        BudgetCommit["I28 Budget COMMIT"]:::impl

        FindingOutboxAppend["DurableOutbox Append Attempt"]:::impl

        FindingCreated["FINDING_CREATED (Authoritative Outbox Event)"]:::impl

        PORT_F006_COM[["PORT: F-006 Settle Consumed"]]

        DedupStage["dedup_stage Clustering"]:::impl

        FinalReport["Canonical Report Output"]:::impl

        Emit["EventBus Notify I32"]:::impl

        PORT_F019_BUS[["PORT: F-019 EventBus Dispatch"]]

        PoisonDLQ["Poison-Pill Quarantine (DLQ Table + Metric)"]:::forbidden


        %% --------------------------------------------------------
        %% OUTBOX FAILURE / REPLAY
        %% --------------------------------------------------------

        NoBus["Outbox Append Failure; WAL Remains Authoritative"]:::vacuous

        WALAuthoritative["WAL Committed State Preserved"]:::impl

        ReplayDispatch["Replay Outbox Append & EventBus Dispatch"]:::impl


        %% --------------------------------------------------------
        %% SETTLEMENT OUTCOMES
        %% --------------------------------------------------------

        SettleRej["Settle REJECTED"]:::impl

        SettleDedup["Settle DEDUPLICATED"]:::vacuous

        SettleNoWal["Settle DROPPED (No wal_id)"]:::forbidden


        %% Settlement entry points
        PORT_F003_SETTLE_BRIDGE --> Coord

        Out --> Coord

        %% Normal settlement chain
        Coord --> Fingerprint
        Fingerprint --> Thaw
        Thaw --> WAL

        WAL -->|"COMMITTED + wal_id I31"| BudgetCommit

        BudgetCommit --> FindingOutboxAppend

        %% Successful authoritative outbox append
        FindingOutboxAppend -->|"append committed"| FindingCreated

        %% Failed outbox append: no false claim that FindingCreated exists
        FindingOutboxAppend -.->|"append failure"| NoBus

        NoBus -->|"no rollback of WAL"| WALAuthoritative
        WALAuthoritative -->|"recovery replay"| ReplayDispatch


        %% Successful finding publication
        FindingCreated --> PORT_F006_COM
        FindingCreated --> DedupStage
        DedupStage --> FinalReport

        FindingCreated -->|"HMAC Receipt Stamp"| Emit

        Emit --> PORT_F019_BUS

        Emit -->|"Max Delivery Retries Exceeded (5x)"| PoisonDLQ


        %% Settlement rejection / dedup / missing WAL
        WAL -->|"FAILED Attempt with wal_id"| SettleRej

        WAL -->|"DEDUPLICATED Claim"| SettleDedup

        WAL -->|"Missing / Corrupt wal_id"| SettleNoWal


        %% Compensation
        SettleRej --> EgressCompensate
        SettleDedup --> EgressCompensate
        SettleNoWal --> EgressCompensate

        EgressCompensate --> PORT_F006_REL[["PORT: F-006 Compensate / Release"]]


        %% Explicit I31 negative constraints
        SettleRej -.->|"FORBIDDEN: no FINDING_CREATED"| FindingCreated
        SettleDedup -.->|"FORBIDDEN: no FINDING_CREATED"| FindingCreated
        SettleNoWal -.->|"FORBIDDEN: no FINDING_CREATED"| FindingCreated
        SettleDrop -.->|"FORBIDDEN: no FINDING_CREATED"| FindingCreated
    end


    %% ============================================================
    %% EGRESS DROP ENTERS SETTLEMENT SEMANTICS
    %% ============================================================

    %% Canonical egress path:
    %% Viol -> Kill -> SettleDrop -> EgressCompensate
    %%
    %% NO second direct Viol -> SettleDrop edge.


    %% ============================================================
    %% CROSS-PLANE RELATIONSHIPS
    %% ============================================================

    EgressCompensate --> PORT_F006_REL

    FindingCreated -->|"authoritative durable event"| Emit

    %% Settlement bridge from F-003 is represented by the port above.
```

### Formal Graph Invariants Table (`FREEZE` Boundary)

| Invariant | Name & Scope | Formal Verification Rule | Verification Level |
|---|---|---|---|
| **`I-GRAPH-01`** | **Topological Need-Edge Equivalence** | $\forall B \in \text{Graph.nodes}, \text{incoming\_edges}(B) \equiv B.\text{needs}$. Only `needs` create Kahn topological ordering; `when` gates are pure runtime predicates. | `PROPERTY-TESTED` (`test_formal_invariants.py`) |
| **`I-GRAPH-02`** | **Conjunctive Dependencies** | Multiple `needs` are strictly conjunctive (AND): $B \text{ unblocks} \iff \forall A \in B.\text{needs}, \text{\_need\_met}(A, B) == \text{True}$. | `MODEL-CHECKED` (`actor_scheduler.py`) |
| **`I-GRAPH-03`** | **Root & Sink Validity** | $\ge 1 \text{ root } (\text{in\_degree}=0, \text{subdomains}), \ge 1 \text{ terminal sink } (\text{out\_degree}=0, \text{sarif\_export})$. All finding producers have directed paths to `reporting`. | `PROPERTY-TESTED` (`graph_builder.py`) |
| **`I-GRAPH-04`** | **Isolated Node Prohibition** | Registered nodes lacking both `needs` and downstream consumers ($\text{in\_degree}=0 \land \text{out\_degree}=0$) fail validation unless declared root/sink. | `FAULT-INJECTED` (`test_formal_invariants.py`) |
| **`I-GRAPH-05`** | **Stage Collision Policy** | Plugins override built-in IDs (`nodes_by_name[n.name] = n`). Duplicate IDs between conflicting plugins fail validation (`ValueError`). | `TESTED` (`graph_builder.py`) |
| **`I-GRAPH-06`** | **Plugin Override Safety** | Plugin overrides MUST preserve dependency monotonicity ($S_{\text{plugin}}.\text{needs} \supseteq S_{\text{builtin}}.\text{needs}$), criticality, producer role, and egress sandbox rules. | `ADVERSARIAL` (`test_formal_invariants.py`) |
| **`I-GRAPH-07`** | **Immutable Sink Membership** | At `FREEZE`, $\text{reporting.needs} = \{ n \in \text{Nodes} \setminus \text{\_REPORT\_SINKS} \mid n \in \text{\_FINDING\_PRODUCER\_STAGES} \lor \text{\_produces\_findings}(n) \}$. Producer role is validated monotonically. | `PROPERTY-TESTED` (`graph_builder.py`) |
| **`I-GRAPH-08`** | **Deterministic GraphGenID** | $\text{GraphGenID} = \text{SHA256}(\text{sorted}(\text{CanonicalNode}(n) \text{ for } n \in \text{Nodes}))$, where $\text{CanonicalNode}(n) = (n.\text{name}, \text{tuple}(\text{sorted}(n.\text{needs})), n.\text{weight}, n.\text{critical}, n.\text{timeout})$. Volatile fields (timestamps/paths) are strictly excluded. | `PROPERTY-TESTED` (`test_formal_invariants.py`) |

---

### Operational Gating Matrix

Persisted terminals live in `StageStatus` (`PENDING`, `RUNNING`, `COMPLETED`, `DEGRADED`, `FAILED`, `SKIPPED_DISABLED`, `SKIPPED_FAILED`). Scheduler-local “ready / deferred / dispatch” are **not** enum values.

| Upstream Status ($A$) | `OutputNonEmpty(A)` / `when` | Downstream Action ($B$) | Typical terminal / skip reason (code) |
|---|---|---|---|
| **`COMPLETED` / `DEGRADED` with output** | `when` true | Dispatch → `RUNNING` → terminal | Normal execution |
| **`COMPLETED` / `DEGRADED` empty (gate false)** | `OutputNonEmpty` false through end of scan | Skip at drain | `reason="condition_never_satisfied"` → `SKIPPED` / `SKIPPED_DISABLED` |
| **`FAILED` on critical upstream** | n/a | Block / skip dependents | `reason="upstream_critical_failure"` → often `SKIPPED_FAILED` path |
| **`SKIPPED_DISABLED` upstream** | n/a | Still satisfies non-join `_need_met` | Downstream may run or skip on its own `when` |
| **Join sinks (`reporting`, …)** | n/a | Wait until **every** producer is terminal (incl. `FAILED`) | Report still emits (partial allowed) |

Other skip reasons observed in `actor_scheduler.py`: `method_not_found`, `suspend_triggered`, `cancelled`, `global_deadline_exceeded`, `speculative_dispatch` (dispatch telemetry, not a skip).

- **Dependency Fulfillment (`_need_met`)**: Non-join stages unblock on $\{ \text{COMPLETED}, \text{DEGRADED}, \text{SKIPPED\_DISABLED} \}$ (plus internal completed/skipped sets). Join sinks unblock on **any** `TERMINAL_STAGE_STATUSES` member (including `FAILED`).
- **Report Integrity**: Partial producer failure still reaches `reporting`; job exit lattice (F-018) maps partial vs fatal (`exit 4` vs `3`).
- **Concurrency & Fairness**: Ready nodes sorted by $(-\text{node.weight}, \text{declaration\_index})$. Retries mint fresh `AttemptId` (I33) and single-use tickets (I30).

---

### Settle Outcome Decision Table

| Stage Attempt Outcome | WAL Result | Settle Status | `FINDING_CREATED` Emitted? | I28 Budget Action | Stage Terminal Status |
|---|---|---|---|---|---|
| **COMPLETED (with findings)** | Committed (`wal_id` assigned) | `COMMITTED` | **Yes** (strict I31) | `COMMIT` (Consumed += units) | `COMPLETED` |
| **COMPLETED (zero findings)** | Committed (`wal_id` assigned) | `COMMITTED` | No | `COMPENSATE` (Available += units) | `COMPLETED` |
| **FAILED / ERROR** | Recorded (`wal_id` assigned) | `REJECTED` | No | `COMPENSATE` (Available += units) | `FAILED` / `DEGRADED` |
| **EGRESS_VIOLATION** | Rejected / Refused | `DROPPED` | No | `COMPENSATE` (Available += units) | `FAILED` |
| **SKIPPED / UNBUDGETED** | Not submitted to WAL | `N/A` | No | `COMPENSATE` (if reserved) | `SKIPPED_DISABLED` |

---

### Subsystem Architecture & Domain Package Mapping

| Domain Subsystem | Active Package Path | Pipeline Attachment Stage | Primary Responsibility & Core Classes |
|---|---|---|---|
| **Asset Discovery & Recon** | `src/recon/` | `subdomains`, `live_hosts`, `urls` | OSINT ingestion, Cloud recon (AWS/Azure/GCP), JS AST parsing, API spec reconstruction (`APISchemaReconstructor`, `CloudBucketScanner`, `AlienURL`). |
| **Vulnerability Analysis** | `src/analysis/` | `passive_scan`, `active_scan`, `semgrep` | Modular active/passive checks, behavioral timing diffing, bug bounty heuristics, AST check registration (`AcceleratedMatcher`, `PluginRegistration`). |
| **Autonomous Exploitation** | `src/exploitation/` | `subdomain_takeover`, `validation` | Proof-of-concept verification, SSRF pivoting, DNS rebinding, deserialization, cloud takeover (`ExploitationCampaign`, `DeserializationExploitationEngine`, `DNSRebindEngine`). |
| **Protocol & Payload Fuzzing**| `src/fuzzing/` | `active_scan` (Optional) | AST grammar mutators (JSON/XML/HTML/SQL), low-level fork server, HTTP/2 framing fuzzer (`BaseASTMutator`, `ForkServer`, `FramingFuzzer`). |
| **Dynamic Detection Runtime** | `src/detection/` | `validation`, `waf` | Multi-family detector bundles, headless browser DOM XSS execution, WAF fingerprinting & evasion (`DetectorBundle`, `DetectionRuntime`, `WAFDetection`). |
| **API Access & Security Tests**| `src/api_tests/` | `access_control` | REST/GraphQL specification parser, BOLA/BFLA access control testing, JWT tampering (`APITester`, `AuthMatrixTester`). |
| **Execution Manifests & Scenarios**| `src/execution/` | `stage_admit.py`, `_run_execution.py` | Active check catalog, isolated execution caching, multi-step scenario models (`ActiveManifestRegistry`, `IsolatedResponseCacheFactory`, `ScenarioEngine`). |
| **Threat Feed & IOC Ingestion** | `src/intel/` | `intelligence` | External threat feed aggregation, indicator extraction, and IOC watchlists (`FeedAggregator`, `Watchlist`, `Indicator`). |
| **Attack Graph & Risk Intelligence**| `src/intelligence/` | `intelligence`, `threat_modeling` | Multi-vulnerability attack chain correlation, CVSS risk modeling, campaign proposals (`ThreatIntelCorrelator`, `AttackChain`, `CalibratedSeverityModel`). |
| **Machine Learning & Triage** | `src/learning/` | Post-Scan Sinks / `F-002` | Run drift tracking, anomaly scoring, FP/TP feedback loops, analyst triage collaboration (`BaselineTracker`, `FeedbackLoop`, `FindingDeduplicator`). |
| **Enterprise GRC & Reporting** | `src/reporting/` | `reporting`, `sarif_export`, `ci_export` | PDF/HTML compliance attestation (SOC2/ISO27001/PCI-DSS), SLA tracking, bug bounty platform clients (`ComplianceAttestation`, `SLATracker`, `AppleClient`, `AWSClient`). |
| **Alert Routing & Escalation** | `src/notifications/`| EventBus Consumer / `F-019` | Outbound alerts (Slack/Discord/Teams/PagerDuty/Email), snooze management, burst escalations (`NotificationBridge`, `Digest`, `SnoozeBook`). |
| **Real-Time Telemetry & Streams**| `src/realtime/`, `src/websocket_server/` | `F-009`, `F-019` | QoS admission shedding (`qos_admit`), standalone high-throughput WebSocket broadcasting (`Broadcaster`, `ConnectionManager`). |

```mermaid
flowchart LR
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph PackageAuthority["Package Path Authority Model"]
        Core["core/frontier/*<br/>(StateAuthority, WAL, CRDT, Raft)"]:::impl
        Facade["frontier/*, tests/test_support/*<br/>(Facades, MemoryJournal Mock)"]:::library
        Cache["cache/*, checkpoint/*<br/>(UnifiedCache, FileCheckpoint)"]:::library
        Domain["intel/*, intelligence/*<br/>(IOC Feeds, Attack Chains)"]:::impl
        
        Facade -->|"forwarding only"| Core
        Cache -->|"non-authoritative"| Core
        Domain -->|"input to scan"| Core
    end
```

---

## F-006 — Leases, time & global budget

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    PORT_F004_RES_IN[["PORT: F-004 Execution Gate Reserve In"]]
    PORT_F004_COM_IN[["PORT: F-004 Settlement Finding Commit In"]]
    PORT_F004_REL_IN[["PORT: F-004 Compensation / Release In"]]

    subgraph ClockModel["Multi-Clock Binding Model (src/core/frontier/state.py)"]
        HLC["Hybrid Logical Clock (HLC)"]:::impl -->|"clock"| EventOrder["Scan Journal Ordering (I23)"]:::impl
        Mono["time.monotonic()"]:::impl -->|"clock"| LeaseTTL["Sublease & Fence Expiration (I19 Monotonic Deadline Comparison)"]:::impl
        Wall["time.time() (UTC)"]:::impl -->|"clock"| AuditTime["Audit Logs & SIEM Export (I22 Admission Gate)"]:::impl
    end

    subgraph LeaseFSM["Lease State Machine & Accounting Deltas (I5, I19, I28, Batched Sublease Pool)"]
        Reserve["ReserveGlobalBudget (Batched Sublease Buffer)"]:::impl -->|"dispatch<br/>(ΔO=+u, ΔA=-u)"| RESERVED["RESERVED<br/>(Outstanding)"]:::impl
        RESERVED -->|"allocate / local sublease consume<br/>(ΔO=0, ΔA=0)"| ACTIVE["ACTIVE<br/>(Outstanding)"]:::impl
        RESERVED -->|"settle findings<br/>(ΔC=+u, ΔO=-u)"| CONSUMED["CONSUMED<br/>(Committed)"]:::impl
        ACTIVE -->|"settle findings<br/>(ΔC=+u, ΔO=-u)"| CONSUMED
        
        RESERVED -->|"cancel / reject<br/>(ΔO=-u, ΔA=+u)"| COMPENSATED["COMPENSATED<br/>(Available)"]:::impl
        ACTIVE -->|"egress abort / immediate budget release<br/>(ΔO=-u, ΔA=+u)"| COMPENSATED
        RESERVED -->|"expire timeout<br/>(ΔO=-u, ΔA=+u)"| EXPIRED["EXPIRED<br/>(Available)"]:::impl
        ACTIVE -->|"TTL elapsed<br/>(ΔO=-u, ΔA=+u)"| EXPIRED
        
        EXPIRED -->|"late reconciliation / compensate (idempotent)<br/>(Δ=0)"| COMPENSATED
        CONSUMED -->|"idempotent re-settle<br/>(Δ=0)"| CONSUMED
        COMPENSATED -->|"idempotent no-op<br/>(Δ=0)"| COMPENSATED
    end

    %% Explicit Cross-Plane Invariant & Port Connections
    LeaseTTL -->|"monotonic timeout check"| EXPIRED
    PORT_F004_RES_IN -->|"reserve request"| Reserve
    PORT_F004_COM_IN -->|"commit units"| CONSUMED
    PORT_F004_REL_IN -->|"release units"| COMPENSATED
```

$$\text{Partition-Local Budget Conservation (I5): } \text{TotalBudget} \equiv \text{Consumed} + \text{Outstanding} + \text{Available} \quad \text{[Verified in Recovery VERIFY\_INVARIANTS]}$$
$$\text{Multi-Raft Cross-Partition Quota Slab Conservation (I26): } \text{TotalBudget} \equiv \text{Consumed} + \text{Outstanding} + \text{SlabReserved} + \text{Available} \quad (\text{SlabReserved} > 0 \text{ in Multi-Raft Mode}) \quad \text{[Verified in Recovery VERIFY\_INVARIANTS]}$$

---

## F-007 — Application state machines & lifecycle coupling

Source: `src/jobs/status.py`, `src/core/models/stage_status.py`, `src/core/contracts/finding_lifecycle.py`, `src/jobs/run_outcome.py`. Absorbed F-008, F-027.

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph Job["JobStatus (src/jobs/status.py)"]
        JP["PENDING"]:::impl --> JS["STARTING"]:::impl
        JP --> JR["RUNNING"]:::impl
        JP --> JF["FAILED (Terminal)"]:::impl
        JP --> JD["STOPPED (Terminal)"]:::impl
        JS --> JR
        JS --> JX["STOPPING"]:::impl
        JS --> JF
        JS --> JD
        JR --> JX
        JR --> JC["COMPLETED (Terminal)"]:::impl
        JR --> JF
        JR --> JD
        JX --> JD
        JX --> JF
    end
    subgraph Stage["Stage CAS (src/core/models/stage_status.py)"]
        SP["PENDING"]:::impl --> SR["RUNNING"]:::impl
        SP --> SSD["SKIPPED_DISABLED (Terminal)"]:::impl
        SP --> SSF["SKIPPED_FAILED (Terminal: Upstream Critical Failure)"]:::impl
        
        SR --> SC["COMPLETED (Terminal)"]:::impl
        SR --> SDG["DEGRADED (Terminal)"]:::impl
        SR --> SF["FAILED"]:::impl
        
        SF -->|"I33 retry"| SR
        SF -->|"retry succeeded"| SC
        SF -->|"retry degraded"| SDG
        SF -->|"retries exhausted"| SSF
    end
    subgraph Finding["Finding Lifecycle & Tri-Axial State Model"]
        %% Axis 1: Surface Lifecycle
        FC["CANDIDATE"]:::impl --> FR["REPORTABLE (Surface Decision)"]:::impl
        FC --> FF["FALSE_POSITIVE (Terminal: Immutable non-repudiation)"]:::impl
        FR -->|"Analyst Triage"| FF

        %% Axis 2: Confidence & Exploitability
        C_HEUR["heuristic_candidate"]:::impl --> C_PASS["passive_only"]:::impl
        C_PASS --> C_VAL["validated"]:::impl
        C_VAL --> C_EXP["exploitable"]:::impl

        %% Axis 3: Operator Ticket Status
        T_OPEN["OPEN"]:::impl --> T_CLOSED["CLOSED"]:::impl

        %% Refinement relation
        C_VAL & C_EXP -.->|"refines confidence of"| FR
    end

    subgraph DerivationLattice["Total Precedence Derivation Lattice (derive_job_and_exit)"]
        Sig["SIGINT / Cancel"]:::impl --> PrecedenceDecision{"Precedence Evaluation<br/>derive_job_and_exit"}:::impl
        SF -->|"fatal infra error / retries exhausted"| PrecedenceDecision
        ConfigSuspend["Hot-Reload Suspend"]:::impl --> PrecedenceDecision
        FR -->|"policy evaluated"| PrecedenceDecision
        SDG & SSF -->|"degraded skips"| PrecedenceDecision
        Unhandled["Unhandled Runtime Exception"]:::impl --> PrecedenceDecision
        SC & SSD & FF -->|"clean outputs"| PrecedenceDecision

        PrecedenceDecision -->|"1. cancel"| Exit130["Exit 130: CANCEL"]:::impl
        PrecedenceDecision -->|"2. fatal/infra"| Exit3["Exit 3: INFRA_FAILURE"]:::impl
        PrecedenceDecision -->|"3. suspend"| Exit7["Exit 7: SUSPEND"]:::impl
        PrecedenceDecision -->|"4. policy violation >= 1"| Exit2["Exit 2: POLICY_GATE"]:::impl
        PrecedenceDecision -->|"5. partial / degraded"| Exit4["Exit 4: PARTIAL_RUN"]:::impl
        PrecedenceDecision -->|"6. runtime error"| Exit1["Exit 1: RUNTIME_ERROR"]:::impl
        PrecedenceDecision -->|"7. clean (0 violations)"| Exit0["Exit 0: CLEAN_RUN"]:::impl

        Exit130 & Exit7 --> J_STOP["Job STOPPED (Terminal)"]:::impl
        Exit3 & Exit1 --> J_FAIL["Job FAILED (Terminal)"]:::impl
        Exit2 & Exit4 & Exit0 --> J_COMP["Job COMPLETED (Terminal)"]:::impl
        
        Exit130 -.->|"precedence: suppresses"| Exit3
        Exit3 -.->|"precedence: suppresses"| Exit7
        Exit7 -.->|"precedence: suppresses"| Exit2
        Exit2 -.->|"precedence: suppresses"| Exit4
        Exit4 -.->|"precedence: suppresses"| Exit1
        Exit1 -.->|"precedence: suppresses"| Exit0
    end
```

---

## F-009 — Resilience: breaker, QoS, PID & bulkhead

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    Load["Target Probe Latency & Error Stream"]:::impl --> PID["AdaptivePIDController (Anti-Windup Clamping + Back-Calculation)"]:::impl
    PID --> Conc["Dynamic Concurrency Window"]:::impl
    Load --> Bulk["BulkheadPool (Unified Endpoint Isolation (scheme,host,port))"]:::impl
    Load --> Bloom["GenerationalBloomFilter (Target FPR 0.001, Auto-Rotation at 0.005)"]:::impl
    Load --> RedisBreaker["RedisClient Circuit Breaker (Local SQLite/Disk Spool Fallback + Health Probe)"]:::impl
    Load --> CLOSED
    subgraph CB["Circuit Breaker (Unified Canonical Endpoint Gate)"]
        CLOSED["CLOSED (Normal Traffic)"]:::impl -->|"Failures >= Threshold (5 consecutive)"| OPEN["OPEN (Tripped / Shedding)"]:::impl
        OPEN -->|"Cooldown Elapsed (20s)"| HALF_OPEN["HALF_OPEN (Trial Generation N)"]:::impl
        HALF_OPEN -->|"Trial Probe OK"| CLOSED
        HALF_OPEN -->|"Trial Probe Failed"| OPEN
    end
    OPEN -->|"set_reserve_gate"| NoTicket["HuntBudget Gate: BudgetReserveDenied (Breaker Open)"]:::forbidden
    Evt["TelemetryEvent Stream"]:::impl --> Q{"qos_admit"}:::impl
    Q -->|P0: Critical Audit| P0["P0: In-Memory Spool + Disk Journal (p0_capacity=1000)"]:::impl
    Q -->|P1: Stage Lifecycle| P1["P1: Reliable Queue Dispatch"]:::impl
    Q -->|P2: Findings Buffer| P2["P2: Coalesced Findings Stream"]:::impl
    Q -->|P3: Periodic Metrics| P3["P3: 1s Rolling Aggregates"]:::impl
    Q -->|P4: Debug Traces| P4["P4: Lowest Priority / First Shed"]:::impl
```

### Telemetry QoS Shedding Decision Matrix (`qos_admit.py`)

| Resource Condition (State Volume / Data Path) | P0 (Critical Audit) | P1 (Stage Events) | P2 (Findings) | P3 (1s Aggregates) | P4 (Debug Traces) |
|---|---|---|---|---|---|
| **Normal (< 85% Disk, < 80% RAM)** | `Admit` (Durable) | `Admit` | `Admit` | `Admit` | `Admit` |
| **Moderate (>= 85% Disk / CPU > 90%)** | `Admit` (Durable) | `Admit` | `Admit` | `Admit` | **`DROP`** |
| **Severe (>= 92% Disk / RAM > 90%)** | `Admit` (Spool) | `Admit` | **`COALESCE`** | **`DROP`** | **`DROP`** |
| **Spool Saturated (> 1000 P0 items)** | `Bounded Backpressure (50ms timeout → Emergency Ring Buffer)` | `Drop` | `Drop` | `Drop` | `Drop` |

---

## F-018 — Failure decision tree, concurrency & I35 recovery

### Total Exit Code Precedence Table (`derive_job_and_exit`)

Strict Priority: $$\text{Cancel (130)} > \text{Infra/Fatal (3)} > \text{Suspend (7)} > \text{Policy Violation (2)} > \text{Partial/Degraded (4)} > \text{Error (1)} > \text{Clean (0)}$$

| Precedence | Observed Pipeline Condition | Exit Code | Terminal JobStatus | Failure Classification (I34) | Operator Action |
|---|---|---|---|---|---|
| **1 (Highest)** | SIGINT / User Cancellation | `130` | `STOPPED` | User Action | Clean shutdown; checkpoint saved |
| **2** | Fatal stage failure / `pipeline_no_output` / Target down | `3` | `FAILED` | `INFRA_FAILURE` | Inspect logs, network, target connectivity |
| **3** | Hot-reload configuration suspend | `7` | `STOPPED` | Policy / Configuration | Worker reloads configuration and resumes |
| **4** | Findings count / CVSS severity exceeds policy rules | `2` | `COMPLETED` | Policy Gate Triggered | Review findings; triage or remediate |
| **5** | Non-fatal stage failure (`DEGRADED` / `SKIPPED_FAILED`) | `4` | `COMPLETED` | `PARTIAL_RUN` | Review partial findings report |
| **6** | Unhandled exception / OOM / Lock collision | `1` | `FAILED` | `RUNTIME_ERROR` | Inspect stack traces; check memory/locks |
| **7 (Lowest)** | All stages completed; findings within policy | `0` | `COMPLETED` | `CLEAN_RUN` | Standard clean pipeline exit |

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph Concurrency["Concurrency & Run Locking (F-039)"]
        ScanReq["cstp scan run target"]:::impl --> Acquire{"Acquire RunLock (Target Name)"}:::impl
        Acquire -->|Collision| CollisionExit["Exit 1 (Lock Collision Error)"]:::forbidden
        Acquire -->|Acquired| Run["Pipeline Execution"]:::impl
        Run --> ReleaseLock["Release RunLock on Exit"]:::impl
    end

    Run --> Precedence{"derive_job_and_exit"}:::impl
    Precedence --> PORT_F007_CAS[["PORT: F-007 JobStatus CAS"]]
    Precedence -->|Cancel Signal| Exit130["Exit 130: STOPPED"]:::impl
    Precedence -->|Fatal Stage / No Output / I35 FAIL_CLOSED| Exit3["Exit 3: FAILED (Infra Failure)"]:::impl
    Precedence -->|Suspend Signal| Exit7["Exit 7: STOPPED (Config Suspend)"]:::impl
    Precedence -->|Policy Violation| Exit2["Exit 2: COMPLETED (Policy Violation)"]:::impl
    Precedence -->|Degraded Probes| Exit4["Exit 4: COMPLETED (Partial Run)"]:::impl
    Precedence -->|Runtime Error / OOM| Exit1["Exit 1: FAILED (Runtime Error)"]:::impl
    Precedence -->|Clean Run| Exit0["Exit 0: COMPLETED (Clean / Pass)"]:::impl
    
    subgraph ErrorMap["Runtime Failure Mappings"]
        CB_Err["Circuit Breaker OPEN"]:::forbidden -->|"HTTP 429 / Throttle"| Exit4
        WAL_Err["WALCorruptionError I15"]:::forbidden -->|"Unrecoverable"| Exit3
        Pol_Err["Policy Gate (No Log)"]:::forbidden -->|"Fail-Closed"| Exit2
        Egress_Err["EgressViolationError I29"]:::forbidden -->|"Scope Guard"| Exit3
        CollisionExit --> Exit1
    end
```

### I34 Formal Failure Recovery Semantics

> **Fail-Closed Principle:** Refuse to apply mutating transition; revert/reserve-compensate or abort with zero committed state change.

| Failure Domain | Retry | Rollback | Compensate | Fail-Closed | Authoritative Resolution |
|---|---|---|---|---|---|
| **WAL Corruption** | No | No | No | **Yes** | Restore from last verified FSM snapshot |
| **Authority Loss** | No | No | No | **Yes** | Await leader election or restart in quorum-1 mode |
| **Replication Divergence** | No | No | No | **Yes** | Restore local FSM from leader PartitionWAL |
| **Event Delivery Failure** | **Yes** | No | No | No | Replay outbox dispatch by `DeliveryId` (I32) |
| **Budget Inconsistency** | No | No | **Yes** | **Yes** | Compensate outstanding I28 reservations |
| **FSM Invariant Violation** | No | No | No | **Yes** | Snapshot re-baseline plus sequential WAL replay |
| **Egress Policy Violation** | No | No | **Yes** | **Yes** | Terminate subprocess; compensate reserved requests (Security Violation → Exit 3) |
| **RunLock Collision** | No | No | No | **Yes** | Abort execution (Exit 1: Target under active scan) |

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    U["UNINITIALIZED"]:::impl --> LS["LOAD_SNAPSHOT"]:::impl
    U --> LW["LOAD_WAL"]:::impl
    U --> Fresh["FRESH<br/>(Clean Run Bootstrap)"]:::impl
    LS --> VS["VERIFY_SNAPSHOT"]:::impl
    VS -->|"partition plane schema mismatch (unsupported version)"| Closed["FAIL_CLOSED (Exit 3)"]:::forbidden
    VS -->|"frontier snapshot schema mismatch"| Fresh
    VS --> LW
    LW --> Rec["RECONCILE_SNAPSHOT_WAL"]:::impl
    Rec -->|"snapshot ahead / truncated partition"| Closed
    Rec -->|"behind or semantically old"| Replay["REPLAY_WAL"]:::impl
    Rec -->|"truncated frontier"| Stale["STALE snapshot then REPLAY_WAL"]:::impl
    Stale --> Replay
    Replay --> FSMR["RECONSTRUCT_FSM (Partition Plane Only)"]:::impl
    FSMR --> Out["RECONCILE_OUTBOX"]:::impl
    Out -->|"FSM without outbox"| Rebuild["Rebuild by EventId"]:::impl
    Out -->|"outbox without FSM (predates commit)"| Orphan["Ignore Pre-Commit Orphan Rows"]:::vacuous
    Rebuild & Orphan --> Del["RECONCILE_DELIVERY"]:::vacuous
    Del -->|"delivery ahead"| Drop["Discard Extra DeliveryIds"]:::vacuous
    Del -->|"delivery missing"| ReplayD["Replay Dispatch I32"]:::vacuous
    Drop & ReplayD --> Inv["VERIFY_INVARIANTS (I30–I33 + I5/I26 Budget Conservation Check)"]:::impl
    Inv -->|"compensation crash: valid lease"| Comp["Idempotent I28 Replay"]:::impl
    Inv -->|"compensation crash: uncompensatable (no reservation / identity lost)"| Closed
    Inv -->|"prerequisite invariant failed"| Closed
    Inv -->|"invariants verified"| Ready["READY (DAG Execution Resume)"]:::impl
    Comp --> Ready
    Fresh -->|"initialize empty state"| Ready
```

---

## F-019 — Operator surface, multi-tenancy & telemetry

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph MultiTenantAuth["Multi-Tenant Boundary & JWT Security Context"]
        Req["Inbound HTTP / WebSocket Request"]:::impl --> AuthMid["Authentication Middleware"]:::impl
        AuthMid --> JWT{"Verify JWT & Tenant"}:::impl
        JWT -->|Valid JWT| Ctx["ContextVar tenant_id & user_id"]:::impl
        JWT -->|Invalid / Expired| Refuse401["HTTP 401 Unauthorized"]:::forbidden
        Ctx --> ScopeCheck{"Verify Tenant Scope Token"}:::impl
        ScopeCheck -->|Mismatch| Refuse403["HTTP 403 Forbidden"]:::forbidden
        ScopeCheck -->|Authorized| ScopeSigned["Signed Context Attached to Request"]:::impl
        ScopeSigned --> Dispatch["FastAPI Route Handlers"]:::impl
    end

    Dispatch --> Hook["useJobMonitor (React Hook)"]:::impl
    Hook -->|"progress stream"| SSE["SSE /api/jobs/:id/progress/stream"]:::impl
    Hook -->|"log stream"| WS["WebSocket /ws/logs/:id"]:::impl
    Hook -->|"triage stream"| Triage["WebSocket /ws/triage/:run_id"]:::impl
    Hook -->|"polling"| REST["REST /api/jobs/:id"]:::impl
    
    WS -.->|"reconnect / poll fallback"| REST
    Triage -.->|"reconnect / poll fallback"| REST
    SSE -.->|"reconnect / poll fallback"| REST
    
    REST & SSE & WS & Triage --> Norm["telemetry/normalizer.ts"]:::impl
    Norm --> Stores["Zustand Stores"]:::impl
    Stores --> Pages["Jobs / Findings / Cockpit UI"]:::impl
    
    subgraph OutboxNotify["Outbox & Telemetry Pipeline"]
        Settle["Settlement COMMITTED"]:::impl ==>|"committed by StateAuthority"| Outbox["L2 DurableOutbox"]:::impl
        Outbox -->|"durable dispatch (async, bounded non-blocking)"| LiveBus["event_bus.EventBus (In-Process Dispatch + Tenant Partitions)<br/><small>Decoupled: Bus fail never uncommits WAL (I32)</small>"]:::impl
        LiveBus --> Fan["Fan-Out (Cap 5)"]:::impl
        App["Pipeline + Dashboard"]:::impl --> Prom["Prometheus Metrics (:9090)"]:::impl
        App --> Logs["tamper-evident audit log (HMAC)"]:::impl
        Prom --> Graf["Grafana Dashboard"]:::impl
    end
```

---

## F-020 — Tests, CI shards & quality policy gates

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph CI_Pipeline["GitHub Actions CI Pipeline (.github/workflows/ci.yml)"]
        Push["Push to main / PR"]:::impl --> Lint["ruff + format + Bandit HIGH"]:::impl
        Push --> Mypy["mypy typecheck"]:::impl
        Push --> TS["typescript tsc --noEmit"]:::impl
        Push --> FE["frontend build"]:::impl
        Push --> Shards["pytest shards (test matrix, fail-fast false)"]:::impl
        Push --> Audit["security-audit"]:::impl
        Push --> Scan["security-scan Semgrep p/ci"]:::impl
        Push --> Hard["hardening check"]:::impl
        Push --> Iac["iac-scan (checkov)"]:::impl
        Shards --> Infra["unit-infra"]:::impl
        Shards --> Core["unit-core"]:::impl
        Shards --> Pipe["unit-pipeline"]:::impl
        Shards --> Recon["unit-recon"]:::impl
        Shards --> Analysis["unit-analysis"]:::impl
        Shards --> Dash["unit-dashboard"]:::impl
        Shards --> Exploit["unit-exploit"]:::impl
        Shards --> App["unit-app"]:::impl
        Shards --> Suites["suites: integration + architecture + regression"]:::impl
        Shards --> Combine["coverage combine job (needs: test)"]:::impl
        Combine --> Cov["coverage fail_under 45"]:::impl
        Lint & Mypy & TS & FE & Combine & Audit & Scan & Hard & Iac --> Ok["CI passed"]:::impl
    end

    subgraph PolicyGateSub["CI/CD Quality Contract & Policy Gates (F-045)"]
        ScanDone["Pipeline Scan Finalized"]:::impl --> PolicyGate{"evaluate_policy"}:::impl
        PolicyGate -->|Critical >= Max Allowed| FailExit["Pipeline Exit 2: Policy Gate Triggered (CI Blocks Merge)"]:::forbidden
        PolicyGate -->|Within Thresholds| PassExit["Pipeline Exit 0: Clean Pass (Export SARIF)"]:::impl
    end
```

---

## F-022 — Gap-analysis status

```mermaid
flowchart LR
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    Raft["Raft transport & consensus"] --> ImplCluster["MultiNodeRaftCluster with configurable peers; majority quorum"]:::impl
    Tickets["Jira ServiceNow DefectDojo"] --> Impl["Implemented"]:::impl
    Policy["Policy via Raft commands"] --> Impl
    Ghost["Multi-host Ghost migration"] --> Open["Open / single-node"]:::specOnly
    WASM["WASM AEVE"] --> Flag["Feature Flagged"]:::specOnly
    PPO["PPO / DRL"] --> Heur["Heuristic stub"]:::specOnly
    GNN["GNN attack graph"] --> Dijk["Dijkstra Shortest-Path Algorithm (Algorithmic Primitive)"]:::library
```

---

## F-025 — Non-authoritative planes, caches & multi-tier storage

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph Config["Three config trees — independent loaders"]
        ScanCfg["ValidatedPipelineConfig JSON"]:::impl
        DashCfg["DashboardConfig DASHBOARD_*"]:::impl
        QueueCfg["QueueConfig QUEUE_*"]:::impl
        ScanCfg --- DashCfg --- QueueCfg
    end

    subgraph MultiTierCache["Multi-Tier Cache & Storage Hierarchy (F-041)"]
        Call["Cache Read Request"]:::impl --> SF["Single-Flight In-Memory LRU (L1)"]:::impl
        SF -->|Hit| Return["Return Cached Output"]:::impl
        SF -->|Miss| Persist["SQLite cache_layer.db / Redis (L2)"]:::impl
        Persist -->|Miss| Origin["Stage Execution (Compute)"]:::impl
        Origin --> Write["Write-Through to L1 & L2"]:::impl
        OutboxEvt["Outbox Invalidation Events<br/>(FINDING_FALSE_POSITIVE, TARGET_REMOVED, POLICY_UPDATED)"]:::impl -->|"CacheGeneration Epoch Bump & Invalidate Keys"| SF & Persist
        Done["Completed Scan Run"]:::impl --> Hot["Hot NVMe Storage (output/run_id/)"]:::impl
        Hot --> Index["index_runs Metadata"]:::impl
        Hot --> PruneCheck{"Older than RETENTION_DAYS (14 Days)?"}:::impl
        PruneCheck -->|Yes| Arch["Gzip Compressed Archive Tier"]:::impl
        Arch --> PruneJob["cstp system cleanup (Pruning)"]:::impl
    end

    subgraph Facades["Thin non-authoritative import facades (Must not mutate authoritative logs)"]
        CacheFacade["src/cache → pipeline.unified_cache"]:::library
        CkptFacade["src/checkpoint → core.checkpoint"]:::library
        FrontFacade["src/frontier facades → core.frontier / infrastructure WAL"]:::library
        MemJ["tests/test_support/journal.py MemoryJournal (Unit-test mock WAL)"]:::library
        CacheFacade -.->|"never truth / read facade"| SF
        CkptFacade -.->|"never truth / read facade"| Persist
        AuthPlane["StateAuthority / PartitionWAL (F-003)"]:::impl -.->|"reject mutation from test mock"| MemJ
    end
```

---

## F-033 — Global invariants I1–I37 enforcement & dependency graph

### Formal Invariant Dependency & Enforcement Semantics

An edge $I_A \longrightarrow I_B$ establishes that invariant $I_A$ is an **architectural / enforcement prerequisite** for $I_B$. The formal guarantees and cryptographic verifications of $I_B$ cannot be soundly admitted or enforced unless $I_A$ is satisfied.

### Formal System Invariant Registry (I1–I37)

| Invariant | Formal Statement | Owning Chart | Enforcing Module | Primary Test Suite | Verification Level |
|---|---|---|---|---|---|
| **I1** | Hash-Chain Continuity ($H_n = \text{SHA256}(H_{n-1} \mathbin{\Vert} \text{CanonicalEncode}(E_n))$) | F-003 | `replicated_log.py` | `test_state_crdt.py` | `PROPERTY-TESTED` |
| **I2** | Log Monotonicity (Index $K_n > K_{n-1}$, Term $T_n \ge T_{n-1}$) | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `PROPERTY-TESTED` |
| **I3** | Committed-State Confinement (Transitions on quorum-committed entries only) | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `FAULT-INJECTED` (single-node quorum-1) |
| **I4** | Aggregate Monotonicity ($\text{version}' = \text{version} + 1$ on `SUCCESS`) | F-003 | `raft_fsm.py` | `test_formal_invariants.py` | `TESTED` |
| **I5** | Global Budget Conservation ($\text{TotalBudget} \equiv \text{Consumed} + \text{Outstanding} + \text{Available}$) | F-006 | `global_coordination.py`, `hunt_budget.py` | `test_formal_invariants.py`, `test_global_invariants.py`, `test_recovery_budget_conservation.py` | `PROPERTY-TESTED` |
| **I6** | Scoped Idempotency ($\forall \text{ valid } \text{cmd\_id}: \text{Count}(\text{Mutations}) \le 1$) | F-003 | `raft_fsm.py` | `test_state_crdt.py` | `PROPERTY-TESTED` |
| **I7** | Singular Partition Ownership (Target aggregate belongs to exactly 1 partition) | F-002 | `global_coordination.py` | `test_formal_invariants.py` | `MODEL-CHECKED` |
| **I8** | Projection Watermark Bound ($\text{ProjectionOffset}(P_x) \le \text{commitIndex}(P_x)$) | F-003 | `projection_stream.py` | `test_formal_invariants.py` | `PRODUCTION-OBSERVED` |
| **I9** | FSM Pure Determinism (`FSM.Apply` zero external I/O, RNG, or clock reads) | F-003 | `raft_fsm.py` | `test_state_crdt.py` | `PROPERTY-TESTED` |
| **I10** | Worker Epoch Fencing ($\text{claim.epoch} < \text{active.epoch} \implies \text{REJECT}$) | F-003 | `raft_fsm.py` | `test_lease_status.py` | `FAULT-INJECTED` |
| **I11** | Cryptographic State Commitment ($\text{State}_A \equiv \text{State}_B \iff \text{StateHash}_A == \text{StateHash}_B$) | F-003 | `raft_fsm.py` | `test_crypto_audit.py` | `PROPERTY-TESTED` |
| **I12** | Snapshot Integrity (Certified snapshot payload hash == header hash) | F-003 | `raft_fsm.py`, `recovery/manager.py` | `test_recovery_protocol.py` | `FAULT-INJECTED` |
| **I13** | Receipt Cryptographic Binding (Leader receipt HMAC validates state hash) | F-003 | `receipt_crypto.py` | `test_crypto_audit.py`, `test_key_rotation.py` | `TESTED` |
| **I14** | Deduplicated Outbox Stream (Domain events deduplicated by `event_id`) | F-003 | `outbox.py` | `test_eventbus_guarantees.py`, `test_poison_pill_dlq.py` | `FAULT-INJECTED` |
| **I15** | Fail-Closed Boundary (Corrupt records or unverified leases abort with 0 mutations) | F-003 | `wal.py`, `failure_model.py` | `test_failure_model.py`, `test_wal_group_commit.py` | `FAULT-INJECTED` |
| **I16** | Replay State Invariance ($\text{Replay}(\text{WAL}[0 \dots N]) \equiv \text{State}_N$) | F-018 | `replay_engine.py` | `test_recovery_protocol.py` | `PROPERTY-TESTED` |
| **I17** | Authority Uniqueness (No non-authoritative subsystem mutates state) | F-002 | `region_model.py` | `test_region_model.py` | `MODEL-CHECKED` |
| **I18** | Stale Command Rejection (Outdated lease epoch / stale placement version rejected) | F-002 | `replicated_log.py` | `test_formal_invariants.py` | `ADVERSARIAL` |
| **I19** | Lease Terminal Linearization (`RESERVED` $\rightarrow$ `CONSUMED` or `COMPENSATED`; `EXPIRED` non-terminal) | F-006 | `lease_status.py` | `test_lease_status.py`, `test_batched_budget_reservations.py` | `MODEL-CHECKED` |
| **I20** | Policy Version Fencing ($\text{expected\_policy\_version} == \text{current\_policy\_version}$) | F-003 | `raft_fsm.py`, `policy_governance.py` | `test_lease_status.py` | `FAULT-INJECTED` |
| **I21** | Projection Recovery Invariance (Sequential outbox replay recovers projection) | F-003 | `outbox.py`, `projection_stream.py` | `test_lease_status.py`, `test_cache_invalidation_protocol.py` | `FAULT-INJECTED` |
| **I22** | Temporal Invariant & Admission Skew Gate (+10s future drift, -5s backward regression at admission) | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `PROPERTY-TESTED` |
| **I23** | Partition Budget Isolation (Subleases isolated per partition, negative balances rejected) | F-006 | `raft_fsm.py`, `state.py` | `test_state_crdt.py`, `test_adaptive_tombstones.py` | `PROPERTY-TESTED` |
| **I24** | Persisted Mesh BootID + Monotonic Nonce Safety | F-002 | `mesh/` | `test_state_crdt.py`, `test_cross_region_consensus.py` | `FAULT-INJECTED` (Nonce reuse forbidden; rotation on BootID bump) |
| **I25** | Partition Policy Rollback Revocation & Watermark Upper Bound | F-003 | `raft_fsm.py` | `test_state_crdt.py` | `TESTED` |
| **I26** | Multi-Raft Quota Slab Conservation ($\text{Total} \equiv \text{Consumed} + \text{Outstanding} + \text{SlabReserved} + \text{Available}$) | F-006 | `global_coordination.py` | `test_formal_invariants.py`, `test_recovery_budget_conservation.py` | `PROPERTY-TESTED` |
| **I27** | Bounded Execution Claims (64KB) & CAS Merkle Evidence | F-004 | `CASStore`, `request_executor.py` | `test_resilience.py`, `test_bloom_fpr_bounds.py` | `PROPERTY-TESTED` |
| **I28** | Hardened Lease State Transitions (`RESERVED` $\rightarrow$ `ACTIVE` $\rightarrow$ `CONSUMED` / `EXPIRED` / `COMPENSATED`) | F-006 | `lease_status.py`, `hunt_budget.py`, `state_authority.py` | `test_global_invariants.py`, `test_state_authority_durability.py`, `test_batched_budget_reservations.py` | `MODEL-CHECKED` |
| **I29** | Scope-Derived Network Egress Enforcement (Egress strictly from `ScopeToken`; metadata denied) | F-004 | `process_sandbox.py`, `egress_context.py`, `shared_sessions.py`, `runtime_browser.py`, `stage_admit.py` | `test_i29_egress_context.py`, `test_sandbox.py`, `test_kernel_egress_isolation.py` | `ADVERSARIAL` (universal network boundary) |
| **I30** | Cryptographic Quartet Ticket Binding (Binds ScopeToken, BudgetReservation, Revision, CommandId) | F-004 | `src/decision/authorization.py`, `stage_admit.py`, `safe_exploiter.py` | `test_global_invariants.py`, `test_formal_invariants.py`, `test_scope_group_lock.py` | `MODEL-CHECKED` |
| **I31** | Settlement-Gated `FINDING_CREATED` Emission (Finding requires durably committed SettlementIntent) | F-033 | `event_bus.py` | `test_global_invariants.py`, `test_structural_dedup.py` | `MODEL-CHECKED` |
| **I32** | Non-Authoritative EventBus Outbox Decoupling (EventBus delivery failure does not uncommit) | F-033 | `event_bus.py` | `test_eventbus_guarantees.py`, `test_poison_pill_dlq.py` | `FAULT-INJECTED` |
| **I33** | Causal Identity Chain ($\text{CommandId} \rightarrow \dots \rightarrow \text{DeliveryId}$) | F-033 | `causal_identity.py` | `test_causal_identity.py` | `PROPERTY-TESTED` |
| **I34** | Formal Failure Recovery Boundaries (8 failure classes with declared recovery action) | F-018 | `failure_model.py` | `test_failure_model.py` | `FAULT-INJECTED` |
| **I35** | Dual-Plane Deterministic Recovery State Machine | F-018 | `recovery_protocol.py` | `test_recovery_protocol.py`, `test_invariant_graph.py`, `test_recovery_budget_conservation.py` | `MODEL-CHECKED` (protocol conformance) |
| **I36** | Single-Writer Regions & Journal-Only Relay | F-002 | `region_model.py` | `test_region_model.py` | `MODEL-CHECKED` |
| **I37** | Zero Dual-Writer Fenced Authority Transfer | F-002 | `authority_transfer.py`, `global_coordination.py`, `migration_handler.py` | `test_authority_transfer.py`, `test_formal_invariants.py` | `MODEL-CHECKED` + `ADVERSARIAL` |

```mermaid
flowchart TD
    classDef impl fill:#1f2937,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef singleNode fill:#1e293b,stroke:#0ea5e9,stroke-width:1px,stroke-dasharray:3 3,color:#fff;
    classDef library fill:#334155,stroke:#64748b,stroke-width:1px,color:#fff;
    classDef specOnly fill:#1e1b4b,stroke:#818cf8,stroke-width:1px,stroke-dasharray:4 4,color:#fff;
    classDef vacuous fill:#27272a,stroke:#71717a,stroke-width:1px,color:#a1a1aa;
    classDef forbidden fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fca5a5;

    subgraph I30_Causality["I30 Authorization Causality Quartet"]
        Scope["ScopeToken Hash"]:::impl
        Res["BudgetReservation ID"]:::impl
        Rev["AuthorityRevision"]:::impl
        Cmd["CommandID"]:::impl
        Scope & Res & Rev & Cmd --> Ticket["AuthorizedExecutionTicket"]:::impl
        Ticket -->|"missing binding"| Reject["Refuse: Ticket Invalid"]:::forbidden
    end
    
    subgraph I33_Identity["I33 Causal Identity Chain"]
        Cmd --> ExecId["ExecutionId"]:::impl
        ExecId --> AttId["AttemptId (retry n)"]:::impl
        AttId --> StlId["SettlementId"]:::impl
        StlId --> WalId["WalId"]:::impl
        WalId --> EvtId["EventId"]:::impl
        EvtId --> DlvId["DeliveryId"]:::impl
    end
    
    subgraph I31_Settlement["I31 Settlement & Outbox Causality"]
        Intent["SettlementIntent"]:::impl --> Durable["WAL wal_id COMMITTED"]:::impl
        Durable -->|"yes"| FindingAllowed["FINDING_CREATED Allowed"]:::impl
        Durable -->|"no"| NoEmit["EventBus Refuses Finding"]:::forbidden
        FindingAllowed --> Outbox["DurableOutboxLedger"]:::impl
        Outbox --> Bus["EventBus (In-Process Dispatch)"]:::impl
        Bus --> Consumers["Observers / UI"]:::impl
        Outbox -->|Append Fail| NoBus["No Bus Notification; Replay Later"]:::vacuous
    end
    
    subgraph ProofGraph["Unified Formal Invariant Proof & Causality Graph (I1–I37)"]
        %% --- Tier 1: Placement, Consensus & Multi-Raft ---
        I1g["I1: Hash-Chain Continuity<br/><small>replicated_log.py [PROPERTY-TESTED]</small>"]:::impl --> I2g["I2: Log Monotonicity<br/><small>replicated_log.py [PROPERTY-TESTED]</small>"]:::impl
        I2g --> I3g["I3: Committed-State Confinement<br/><small>replicated_log.py [FAULT-INJECTED]</small>"]:::impl
        I3g --> I7g["I7: Singular Partition Ownership<br/><small>global_coordination.py [MODEL-CHECKED]</small>"]:::impl
        I7g --> I17g["I17: Authority Uniqueness<br/><small>region_model.py [MODEL-CHECKED]</small>"]:::impl
        I17g --> I36g["I36: Single-Writer Region Relay<br/><small>region_model.py [MODEL-CHECKED]</small>"]:::impl
        I36g --> I37g["I37: Zero Dual-Writer Transfer Fence<br/><small>authority_transfer.py [PRODUCTION-OBSERVED]</small>"]:::impl
        I2g --> I4g["I4: Aggregate Monotonicity<br/><small>raft_fsm.py [TESTED]</small>"]:::impl
        I18g["I18: Stale Command Rejection<br/><small>replicated_log.py [ADVERSARIAL]</small>"]:::impl --> I36g

        %% --- Tier 2: Durability, Clock Admission & Zero-I/O FSM ---
        I22g["I22: Clock Skew Admission Gate<br/><small>replicated_log.py [PROPERTY-TESTED]</small>"]:::impl --> I4g
        I4g --> I11g["I11: Cryptographic State Commitment<br/><small>raft_fsm.py [PROPERTY-TESTED]</small>"]:::impl
        I11g --> I12g["I12: Snapshot Integrity<br/><small>raft_fsm.py [FAULT-INJECTED]</small>"]:::impl
        I12g --> I15g["I15: Fail-Closed Corruption Boundary<br/><small>wal.py [FAULT-INJECTED]</small>"]:::impl
        I15g --> I9g["I9: Pure FSM Determinism<br/><small>raft_fsm.py [PROPERTY-TESTED]</small>"]:::impl
        I9g --> I10g["I10: Worker Epoch Fencing<br/><small>raft_fsm.py [FAULT-INJECTED]</small>"]:::impl
        I9g --> I13g["I13: Receipt HMAC Binding<br/><small>receipt_crypto.py [TESTED]</small>"]:::impl
        I9g --> I14g["I14: Deduplicated Outbox Stream<br/><small>outbox.py [FAULT-INJECTED]</small>"]:::impl
        I9g --> I16g["I16: Replay State Invariance<br/><small>replay_engine.py [PROPERTY-TESTED]</small>"]:::impl
        I14g --> I8g["I8: Projection Watermark Bound<br/><small>projection_stream.py [PRODUCTION-OBSERVED]</small>"]:::impl

        %% --- Tier 3: Quota Slabs, Budget Conservation & Leases ---
        I26g["I26: Quota Slab Conservation<br/><small>global_coordination.py [PROPERTY-TESTED]</small>"]:::impl --> I5g["I5: Universal Budget Conservation<br/><small>global_coordination.py [PROPERTY-TESTED]</small>"]:::impl
        I5g --> I6g["I6: Scoped Idempotency<br/><small>raft_fsm.py [PROPERTY-TESTED]</small>"]:::impl
        I6g --> I19g["I19: Lease Terminal Linearization<br/><small>lease_status.py [MODEL-CHECKED]</small>"]:::impl
        I19g --> I20g["I20: Policy Version Fencing<br/><small>policy_governance.py [FAULT-INJECTED]</small>"]:::impl
        I19g --> I21g["I21: Projection Recovery Invariance<br/><small>outbox.py [FAULT-INJECTED]</small>"]:::impl
        I19g --> I28g["I28: Hardened Lease Transitions<br/><small>hunt_budget.py [MODEL-CHECKED]</small>"]:::impl

        %% --- Tier 4: CRDT State, Bulkheads, Sandboxing & Causality ---
        I23g["I23: Partition Budget Isolation<br/><small>state.py [PROPERTY-TESTED]</small>"]:::impl --> I25g["I25: Policy Revocation Watermark<br/><small>raft_fsm.py [TESTED]</small>"]:::impl
        I25g --> I24g["I24: Mesh BootID Nonce Safety<br/><small>mesh/ [FAULT-INJECTED]</small>"]:::impl
        I27g["I27: Bounded Claims & CAS Merkle Evidence<br/><small>resilience.py [PROPERTY-TESTED]</small>"]:::impl --> I29g["I29: Universal Network Egress Authority<br/><small>egress_context.py [ADVERSARIAL]</small>"]:::impl
        I29g --> I30g["I30: Authorization Causality Quartet<br/><small>authorization.py [MODEL-CHECKED]</small>"]:::impl
        I22g --> I30g
        I30g --> I33g["I33: Causal Identity Chain<br/><small>causal_identity.py [PROPERTY-TESTED]</small>"]:::impl

        %% --- Tier 5: Settlement, Outbox Decoupling & Recovery ---
        I30g & I28g & I33g --> I31g["I31: Settlement-Gated Finding Emission<br/><small>event_bus.py [MODEL-CHECKED]</small>"]:::impl
        I31g --> I32g["I32: Outbox Decoupling Non-Authority<br/><small>event_bus.py [FAULT-INJECTED]</small>"]:::impl
        I28g & I32g --> I34g["I34: Failure Recovery Boundaries<br/><small>failure_model.py [FAULT-INJECTED]</small>"]:::impl
        I34g & I16g --> I35g["I35: Dual-Plane Recovery Protocol<br/><small>recovery_protocol.py [MODEL-CHECKED]</small>"]:::impl
        I37g --> I35g
    end
```

---

## Retired Chart Registry

In accordance with §0 (Maintenance Contract), retired IDs are preserved as stable pointers below:

| Retired ID | Original Scope | Survivor Section |
|---|---|---|
| `F-005` | Live Scan Stage Path | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-008` | Finding Lifecycle States | → [F-007](#f-007--application-state-machines--lifecycle-coupling) |
| `F-010` | Tool Execution Subprocess | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-011` | Budget State Machine | → [F-006](#f-006--leases-time--global-budget) |
| `F-012` | Network Raft Transport | → [F-003](#f-003--authority-plane-raft-l0l5--security-keys) |
| `F-013` | Checkpoint & FSM Rebuild | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-014` | Zero I/O FSM Determinism | → [F-003](#f-003--authority-plane-raft-l0l5--security-keys) |
| `F-015` | Process Sandbox Enforcement | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-016` | Durable Outbox Delivery | → [F-003](#f-003--authority-plane-raft-l0l5--security-keys) |
| `F-017` | Event Delivery Semantics | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-021` | Multi-Region Gossip Protocol | → [F-002](#f-002--system-topology-regions--deployment) |
| `F-023` | Frontend WebSocket Feeds | → [F-019](#f-019--operator-surface-multi-tenancy--telemetry) |
| `F-024` | Circuit Breaker Shedding | → [F-009](#f-009--resilience-breaker-qos-pid--bulkhead) |
| `F-026` | Telemetry Event Normalizer | → [F-019](#f-019--operator-surface-multi-tenancy--telemetry) |
| `F-027` | Job Status CAS Machine | → [F-007](#f-007--application-state-machines--lifecycle-coupling) |
| `F-028` | Multi-Tier Cache Layer | → [F-025](#f-025--non-authoritative-planes-caches--multi-tier-storage) |
| `F-029` | Recon Validation Stage | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-030` | Priority QoS Admission | → [F-009](#f-009--resilience-breaker-qos-pid--bulkhead) |
| `F-031` | Telemetry Dispatch Normalizer | → [F-019](#f-019--operator-surface-multi-tenancy--telemetry) |
| `F-032` | Storage Tiering & Archival | → [F-025](#f-025--non-authoritative-planes-caches--multi-tier-storage) |
| `F-034` | Plane Boundary & Ownership | → [F-003](#f-003--authority-plane-raft-l0l5--security-keys) |
| `F-035` | Plugin Load & Runtime DAG | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-036` | Scope & Continuous Egress | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-037` | Cryptographic Key Hierarchy | → [F-003](#f-003--authority-plane-raft-l0l5--security-keys) |
| `F-038` | Monotonic Clocks & Leases | → [F-006](#f-006--leases-time--global-budget) |
| `F-039` | Concurrency & Run Locking | → [F-018](#f-018--failure-decision-tree-concurrency--i35-recovery) |
| `F-040` | Deployment Topology Model | → [F-002](#f-002--system-topology-regions--deployment) |
| `F-041` | Persistence Tiering & Retention | → [F-025](#f-025--non-authoritative-planes-caches--multi-tier-storage) |
| `F-042` | Finding Deduplication CRDT | → [F-004](#f-004--live-scan-path-execution-dag--egress-sandbox) |
| `F-043` | Multi-Tenant Partitioning | → [F-019](#f-019--operator-surface-multi-tenancy--telemetry) |
| `F-044` | Schema Upcasting Evolution | → [F-003](#f-003--authority-plane-raft-l0l5--security-keys) |
| `F-045` | CI/CD Quality Policy Gates | → [F-020](#f-020--tests-ci-shards--quality-policy-gates) |

---

## System Tunables & Environment Configuration

| Variable | Default Value | Owning Subsystem | Description |
|---|---|---|---|
| `DASHBOARD_HOST` | `127.0.0.1` | FastAPI Dashboard | Binding network interface for REST API |
| `DASHBOARD_PORT` | `8000` | FastAPI Dashboard | Listening HTTP port |
| `DASHBOARD_WORKERS` | `1` | FastAPI Dashboard | Uvicorn worker process count |
| `MESH_LEADER_ELECTION_TIMEOUT_SEC` | `10.0` | Mesh Consensus | Raft-lite Redis lease consensus timeout |
| `MESH_PEER_RATE_LIMIT_PPS` | `200` | Mesh Gossip | Maximum gossip packets per second per peer |
| `OBSERVABILITY_METRICS_PORT` | `9090` | Observability | Prometheus metrics scraping port |
| `PROMETHEUS_HOST` | `127.0.0.1` | Observability | Prometheus scrape binding address (localhost default) |
| `PROMETHEUS_REQUIRE_MTLS` | `false` | Observability | Require mTLS client certificates for Prometheus scrapes |
| `WAL_GROUP_COMMIT_BATCH_SIZE` | `64` | Partition WAL | Group commit entry batch size before fsync |
| `WAL_GROUP_COMMIT_WINDOW_MS` | `1.0` | Partition WAL | Group commit maximum window duration in ms |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | Observability | OpenTelemetry OTLP collector gRPC endpoint |
| `AUTHORITY_SIGNING_KEY_ID` | `authority-hmac-v1` | Frontier Crypto | Key identifier for HMAC receipt verification |
