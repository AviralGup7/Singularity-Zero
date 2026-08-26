# Flowchart Atlas

Visual graphs of the living docs under `docs/`. Charts are the map; the linked markdown files remain the specification.

**One file. Merged when overlapping.** Similar, nested, or part-of-each-other flows share a single survivor chart. Retired ids stay as headings that point at the survivor — they are not rewritten away and their ids are never reused.

---

## 0. Maintenance Contract — HARD RULE

> **Complete rewrite of this file is forbidden.**
>
> This atlas is an append-only-by-default living document.
>
> | Action | Allowed? | When |
> |---|---|---|
> | Add a new `F-NNN` chart | Yes | A new doc, subsystem, or lifecycle appears |
> | Merge overlapping charts into one survivor | Yes | Charts are similar, nested, or part of each other |
> | Retire a chart heading after merge | Yes | Leave `RETIRED → F-XXX`; do not reuse the id |
> | Edit / improve an existing chart | Yes | The source doc or code changed |
> | Rename a node or edge | Yes | The name in code/docs changed |
> | Delete a chart or a portion of a chart | **Only if** that portion's subject was actually deleted from the repo/docs |
> | Replace the whole file | **Never** |
> | Wipe sections to "start over" | **Never** |
> | Reuse a retired `F-NNN` id | **Never** — mark the section `RETIRED` and leave the heading |
>
> How to change this file:
>
> 1. Locate the stable chart id (`F-001` …).
> 2. Patch only that section (or append a new id).
> 3. Update the Atlas Index row for that id.
> 4. Record the change in the Changelog at the bottom.
>
> Agents and humans must treat a full-file overwrite as a defect.

---

## Legend & Status Vocabulary

Every graph in this atlas adheres to a standardized visual taxonomy:

### Edge Semantics
- `A --> B` : **Authoritative transition / synchronous flow** — verified data or control handoff.
- `A ==> B` : **Primary / hot path execution** — default DAG execution or fast-path route.
- `A -.-> B` : **Constraint / Non-Effect / Invariant assertion** (e.g. `L5 -.-> L0` forbidden, `FC -.-> FV` refinement).
- `PORT_F006[["→ F-006 RESERVED"]]` : **Explicit cross-chart interface port** connecting partitioned diagrams.

### Node Status Classes (`classDef`)
- `:::impl` : **Fully Implemented** — live production code in `src/`.
- `:::singleNode` : **Single-Node Quorum-1** — operating in-process or local cluster mode.
- `:::library` : **Library / Extensible Component** — imported as utility, not a stand-alone daemon.
- `:::specOnly` : **Specification / Future Plane** — formalized target architecture not yet active in live CLI.
- `:::vacuous` : **Vacuous / No-Op State** — rehydration or check step that is empty by design in normal runs.
- `:::forbidden` : **Forbidden / Fail-Closed** — explicitly illegal transition rejected by runtime gates.

---

## Atlas Index

Live charts only. Retired ids are one-line headings preserved after the live charts in the Retired Chart Registry (ids are never reused).

| Id | Chart | Source Specification & Symbols | Absorbed | Verified |
|---|---|---|---|---|
| F-001 | Documentation portal map | [index.md](index.md), [getting-started.md](getting-started.md), [deployment.md](deployment.md) | — | 2026-08-26 (`9cb16b25`) |
| F-002 | System topology, regions & deployment | [architecture-overview.md](architecture-overview.md), [multi-region.md](multi-region.md), [deployment.md](deployment.md), `region_model.py` (I36), `authority_transfer.py` (I37), `launcher.py` | F-021, F-040 | 2026-08-26 (`eb763fe7`) |
| F-003 | Authority plane, Raft L0–L5 & security keys | [architecture.md](architecture.md), [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md), `replicated_log.py`, `receipt_crypto.py`, `schema_upcaster.py`, `state.py` | F-012, F-014, F-016, F-034, F-037, F-044 | 2026-08-26 (`95ed3b7e`) |
| F-004 | Live scan path, execution DAG & egress sandbox | [architecture.md](architecture.md), [codebase.md](codebase.md), [commands.md](commands.md), `graph_builder.py`, `_run_execution.py`, `stage_admit.py`, `process_sandbox.py`, `dedup/` | F-005, F-010, F-013, F-015, F-017, F-029, F-035, F-036, F-042 | 2026-08-26 (`1ebc2754`) |
| F-006 | Leases, time & global budget | [architecture.md](architecture.md), [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md), `hunt_budget.py`, `lease_status.py` | F-011, F-038 | 2026-08-26 (`d49bfb05`) |
| F-007 | Application state machines & lifecycle coupling | `src/jobs/status.py`, `src/core/models/stage_status.py`, `src/core/contracts/finding_lifecycle.py`, `run_outcome.py` | F-008, F-027 | 2026-08-26 (`12113b4b`) |
| F-009 | Resilience: breaker, QoS, PID & bulkhead | [architecture.md](architecture.md), [performance.md](performance.md), `resilience/`, `prioritized_broker.py`, `qos_admit.py` | F-024, F-030 | 2026-08-26 (`e7803858`) |
| F-018 | Failure decision tree, concurrency & I35 recovery | [FAILURE_MODES.md](FAILURE_MODES.md), `failure_model.py` (I34), `recovery_protocol.py` (I35), `recovery/manager.py`, `run_lock.py` | F-039 | 2026-08-26 (`6843c35b`) |
| F-019 | Operator surface, multi-tenancy & telemetry | [frontend.md](frontend.md), [api-reference.md](api-reference.md), [OBSERVABILITY_CATALOG.md](OBSERVABILITY_CATALOG.md), `telemetry/normalizer.ts`, `middleware.py` | F-023, F-026, F-031, F-043 | 2026-08-26 (`479c106d`) |
| F-020 | Tests, CI shards & quality policy gates | [testing.md](testing.md), [ci-cd-integration.md](ci-cd-integration.md), `.github/workflows/ci.yml`, `run_outcome.py` | F-045 | 2026-08-26 (`479c106d`) |
| F-022 | Gap-analysis status | [GAP_ANALYSIS.md](GAP_ANALYSIS.md) | — | 2026-08-26 (`479c106d`) |
| F-025 | Non-authoritative planes, caches & multi-tier storage | [architecture/cache-unification.md](architecture/cache-unification.md), [environment-variables.md](environment-variables.md), `src/infrastructure/cache/`, `maintenance.py` | F-028, F-032, F-041 | 2026-08-26 (`479c106d`) |
| F-033 | Global invariants I1–I37 proof graph & registry | `invariant_graph.py`, `global_invariants.py`, `causal_identity.py`, `event_delivery.py` | — | 2026-08-26 (`7a2bb407`) |


---

## F-001 — Documentation portal map

Source: [index.md](index.md)

```mermaid
flowchart TD
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
```

Portal lists only files that exist. `CONTRIBUTING.md` / `BENCHMARK.md` / `CHANGES.md` are not in the repo.

---

## F-002 — System topology, regions & deployment

Source: [architecture-overview.md](architecture-overview.md), [multi-region.md](multi-region.md), [deployment.md](deployment.md), `src/core/frontier/region_model.py` (I36), `src/core/frontier/authority_transfer.py` (I37), `src/cli/launcher.py`. Absorbed F-021, F-040.

A region is a placement/replica boundary, not a second authority. Only the current leader home admits commands. Home moves only as I37 `OWNED → FENCED → OWNED` (nobody writes in the gap; fenced placement also refuses `settle_stage_output`). If a transfer stalls or times out, `abort_transfer` reverts to `OWNED` on the original home with an incremented epoch. The relay is journal-only (`reconcile_with_peer` drops settlement/command rows). Live CLI is single-home `local` — the two-region mermaid is the I36/I37 spec, not a running mesh.

```mermaid
flowchart TD
    subgraph Deployment["Deployment Process Topology (launcher.py)"]
        Browser["React 19 Dashboard (:5173 / :8000)"]:::impl <-->|"REST / WebSocket"| API["FastAPI Dashboard Server (:8000)"]:::impl
        API <-->|"Redis Job Queue & Streams"| Worker["Pipeline Background Worker Daemon"]:::impl
        Worker <-->|"Local Sandbox"| Tools["Security Tool Subprocesses (nuclei, httpx, etc.)"]:::impl
        Worker <-->|"Prometheus /metrics (:9090)"| PromSink["Prometheus / Grafana"]:::impl
    end
    
    Worker --> Orch["Pipeline Orchestrator"]:::impl
    Orch --> Engines["Recon / Analysis / Fuzz / Exploit"]:::impl
    Orch --> State["WAL / CRDT / Cache / Mesh"]:::impl
    Engines --> Sinks["Learning + Reporting"]:::impl
    State --> Sinks
    
    subgraph RegionA["Region A (Leader Home)"]
        GA["Gossip Node A1"]:::impl
        OA["P-0000 Leader + Partition Log"]:::impl
        JA["FrontierWAL Journal"]:::impl
        RA["Redis Stream Journal"]:::impl
        OA --> JA --> RA
    end
    subgraph RegionB["Region B (Read Replica)"]
        GB["Gossip Node B1"]:::singleNode
        OB["Fail-Closed for Mutations"]:::forbidden
        JB["FrontierWAL Replica (Monotonic Read)"]:::specOnly
        RB["Redis Stream Replica"]:::specOnly
        JB --> RB
    end
    State --> OA
    GA <-->|"SWIM UDP AES-256-GCM"| GB
    RA -->|"WALReplicationRelay (Scan Journal Only I36)"| RB
    OB -.->|"must not commit settlements"| Forbidden["I36 / I37 Refuse Foreign Writer"]:::forbidden
    
    subgraph I37_Transfer["I37 Authority Transfer Lifecycle"]
        OwnedA["Region A: OWNED (Writes Active)"]:::impl --> Fence["initiate_transfer: FENCED (Zero-Writer Gap)"]:::impl
        Fence --> OwnedB["activate_ownership: Region B OWNED"]:::impl
        Fence -->|"abort / timeout"| AbortA["abort_transfer: Region A OWNED (Epoch Bumped)"]:::impl
        Fence -.->|"A stale attempt"| RejectA["Refuse: Stale Epoch / Token"]:::forbidden
        Fence -.->|"B early mutation"| RejectB["Refuse: Partition FENCED"]:::forbidden
    end
```

---

## F-003 — Authority plane, Raft L0–L5 & security keys

Source: [architecture.md](architecture.md), [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md), `src/core/frontier/replicated_log.py`, `src/core/frontier/receipt_crypto.py`, `src/core/contracts/schema_upcaster.py`, `src/core/frontier/state.py`. Absorbed F-012, F-014, F-016, F-034, F-037, F-044.

```mermaid
flowchart TD
    subgraph Upcasting["Schema Upcasting & Key Hierarchy (F-044, F-037)"]
        OldPayload["Legacy Command / Payload (v1 / v2)"]:::impl --> Upcaster["SchemaUpcaster (v1 → v2 → v3)"]:::impl
        Upcaster --> Envelope["Canonical Envelope"]:::impl
        MasterKey["AUTHORITY_SIGNING_KEY / APP_SECRET_KEY"]:::impl --> Derive["HMAC Key Derivation"]:::impl
        Derive --> ReceiptKey["CommandReceipt Key"]:::impl
        Derive --> MeshKey["MESH_SECRET (AES-256-GCM)"]:::impl
        Derive --> JWTKey["JWT Session Key"]:::impl
        MasterKey -.->|Missing Env| Fallback["Process-Local Random Key"]:::vacuous
    end

    subgraph PartitionPlane["Partition Plane (Raft / PartitionWAL L0–L3) — AUTHORITATIVE FOR GOVERNANCE"]
        Tuner["Policy Governance Gate"]:::impl --> Promo["Promote / Rollback Policy"]:::impl
        Promo --> Envelope
        Envelope --> Admit["Admission Clock-Skew Check I22 (< 1000ms)"]:::impl
        Admit --> Log["ReplicatedPartitionLog"]:::impl
        
        subgraph Raft["L0: Raft Distributed Commit"]
            Leader["Leader PartitionWAL L0"]:::impl
            F1["Follower PartitionWAL"]:::library
            Leader -->|"AppendEntries"| F1
            F1 -->|"ACK (Quorum-1 Live)"| Leader
            Leader --> Commit["Advance commitIndex"]:::impl
        end
        Log --> Leader
        Commit --> Apply["L1: FSM.Apply (Pure Deterministic Zero I/O)"]:::impl
        Apply --> StateHash["Deterministic State Hash (SHA-256)"]:::impl
        StateHash --> Receipt["HMAC-SHA256 CommandReceipt (Signed by ReceiptKey)"]:::impl
        Apply --> Outbox["L2: DurableOutboxLedger"]:::impl
        Outbox --> Proj["L3: Materialized Projections (GlobalBudgetAggregate P-0000)"]:::impl
    end
    
    subgraph FrontierPlane["Frontier Plane (FrontierWAL / CRDT) — AUTHORITATIVE FOR SCAN DISCOVERY"]
        F_Targets["Target Subdomains & URLs"]:::impl
        F_Findings["Findings CRDT Bag (REPORTABLE)"]:::impl
        F_Candidates["Candidates CRDT Bag (Non-Reportable)"]:::impl
        F_Tombstones["Compaction Tombstones (1h TTL)"]:::impl
        F_Targets --> F_Findings
        F_Targets --> F_Candidates
        F_Findings --> F_Tombstones
        F_Candidates --> F_Tombstones
    end
    
    Outbox -->|"HMAC Receipt"| Bridge["SettlementCoordinator Bridge"]:::impl
    Bridge --> F_Findings
    Proj --> Cache["L4: Caches & Telemetry"]:::impl
    Cache --> UI["L5: Presentation & Dashboard"]:::impl
    UI -.->|"must never author L0–L3"| Forbidden["Forbidden as Truth Source"]:::forbidden
```

Live CLI is single-node quorum-1. `NetworkRaftTransport` stays LIBRARY. `attach_pipeline_authority` is `src/pipeline/authority_bootstrap.py`.

---

## F-004 — Live scan path, execution DAG & egress sandbox

Source: [architecture.md](architecture.md), [codebase.md](codebase.md), [commands.md](commands.md), [architecture/execution-request-contract.md](architecture/execution-request-contract.md), `src/pipeline/services/pipeline_orchestrator/graph_builder.py`, `src/sandbox/process_sandbox.py`, `src/analysis/dedup/`. Absorbed F-005, F-010, F-013, F-015, F-017, F-029, F-035, F-036, F-042.

```mermaid
flowchart TD
    subgraph Init["CLI Launch & DAG Construction (F-035)"]
        CSTP["cstp CLI"]:::impl --> Launch["launch: Dashboard + Background Worker"]:::impl
        CSTP --> Scan["scan run: Runtime Pipeline"]:::impl
        CSTP --> Sys["system doctor / status / setup / cleanup"]:::impl
        Scan --> Runtime["src.pipeline.runtime"]:::impl
        Runtime --> Bind["register_process_bindings"]:::impl
        Bind --> Recover["RecoveryManager (I35 Snapshot + WAL Protocol)"]:::impl
        Recover --> Verify["verify_checkpoint_against_fsm"]:::impl
        Recover --> Auth["attach_pipeline_authority"]:::impl
        Auth --> Stamp["ctx.budget_enforcer + authorizer"]:::impl
        BaseDAG["Base STAGE_GRAPH (16 nodes)"]:::impl --> PluginReg["Dynamic Plugin Discovery"]:::impl
        PluginReg --> PluginVal["Plugin Schema Validation"]:::impl
        PluginVal --> Inject["_join_finding_producers Dynamic Injection"]:::impl
        Inject --> Sub["subdomains"]:::impl
    end

    Stamp --> Sub
    subgraph DAG["Runtime STAGE_GRAPH (graph_builder.py)"]
        Sub --> Takeover["subdomain_takeover"]:::impl
        Sub --> LiveH["live_hosts"]:::impl
        LiveH --> WAF["waf"]:::impl
        LiveH --> Urls["urls"]:::impl
        Urls --> ReconVal["recon_validation"]:::impl
        Urls --> GitDiff["git_diff_crawl"]:::impl
        Urls --> Params["parameters"]:::impl
        Urls & Params & WAF --> Rank["ranking"]:::impl
        Rank & LiveH & Urls --> Passive["passive_scan"]:::impl
        Passive --> Active["active_scan"]:::impl
        Passive --> Semgrep["semgrep"]:::impl
        Passive --> Nuclei["nuclei"]:::impl
        Rank & Passive --> Access["access_control"]:::impl
        Passive & Active --> Val["validation"]:::impl
        Passive & Active & Nuclei & Val --> Intel["intelligence"]:::impl
        Intel --> Threat["threat_modeling"]:::impl
        Intel & Nuclei & Access & Threat & Val & Semgrep & Passive & Takeover --> Report["reporting"]:::impl
        Report --> Sarif["sarif_export"]:::impl
        Report --> CiExp["ci_export"]:::impl
        Report --> Dedup["dedup_stage"]:::impl
        Sca["sca_scan / container_scan / iac_scan / git_secret_scan"]:::impl -.->|"runtime _join_finding_producers"| Report
    end

    DAG -->|"per ready node"| Req["ExecutionRequest + ScopeToken"]:::impl
    
    subgraph Sandbox["Execution Gate & Continuous Egress Sandbox (F-036)"]
        Req --> Budget{"HuntBudget.reserve"}:::impl
        Budget -->|Exhausted| Rej["ScopeAuthorizationError (Stage Skipped / Degraded)"]:::forbidden
        Budget -->|OK| Ticket["AuthorizedExecutionTicket I30 (Binds Quartet)"]:::impl
        Ticket --> Consume["ExecutionAuthorizer.consume (Single-Use, Zero Commit)"]:::impl
        Consume --> PreCheck["Stage Admit Pre-Flight Egress Check"]:::impl
        PreCheck --> Exec["Tool Subprocess Execution (Timeouts, Stdio Capture)"]:::impl
        Exec --> SocketConn["Socket Connect / DNS Resolution"]:::impl
        SocketConn --> EgressGuard{"In-Scope IP Guard"}:::impl
        EgressGuard -->|In Scope| Out["StageOutput / RawExecutionClaim"]:::impl
        EgressGuard -->|Out of Scope / TOCTOU| Viol["EgressViolationError --> Kill Subprocess + Release Budget"]:::forbidden
    end

    subgraph SettlementPipeline["Settlement & Deduplication Pipeline (F-042)"]
        Out --> Coord["SettlementCoordinator (Claim Validation)"]:::impl
        Coord --> Fingerprint["SHA256 Fingerprint (tool|target|type|endpoint)"]:::impl
        Fingerprint --> Thaw["_to_mutable Record Format"]:::impl
        Thaw --> WAL["StateAuthority.append SettlementIntent"]:::impl
        WAL -->|COMMITTED + wal_id I31| CommitB["I28 Budget COMMIT --> Outbox FINDING_CREATED"]:::impl
        CommitB --> DedupStage["dedup_stage Clustering"]:::impl
        DedupStage --> FinalReport["Canonical Report Output"]:::impl
        CommitB -->|HMAC Receipt| Emit["EventBus Notify I32"]:::impl
        CommitB -->|Outbox Fail| NoBus["No Bus Notify; WAL Committed; Replay Later"]:::vacuous
        WAL -->|FAILED Attempt with wal_id| FailedId["Settle REJECTED --> I28 Budget RELEASE (No FINDING_CREATED)"]:::impl
        WAL -->|REJECTED / DEDUPLICATED / No wal_id| Silent["Silent Settle Drop --> I28 Budget RELEASE"]:::impl
    end
```

Per-stage admit is `stage_admit.admit_stage`: authorize (I28 **reserve**) → **consume ticket (I30 single-use only)** → `ProcessSandbox.check_egress` (metadata-guard) → run. `ProcessSandbox.run` is unused. I28 **commit/release** is only at `SettlementCoordinator` / `BudgetProjection` (stage settle COMMIT on COMPLETED, RELEASE on FAILED/SKIPPED; execution settle same). Tickets use partition `P-0000`. Attach failure is fail-closed exit 3; `apply_authority_recovery` runs after attach. FAILED stages still `settle_stage_output`; the settle **status** name is `REJECTED` (wal_id present). `reporting.needs` includes every finding producer (`_join_finding_producers`, including `sca_scan` / `git_secret_scan`). Report sinks alone do not pin low-value optional producers in the planner. Canonical `findings` CRDT bag is REPORTABLE surface (unstamped rows promote); evidence bags cannot bypass. `attach_pipeline_authority` is the only writer.


Import-time `STAGE_GRAPH` in `_constants.py` ≠ runtime `build_pipeline_graph` after plugins. Planner prefers the runtime Graph; `resolve_stage_timeout` prefers the runtime Graph node timeout, then `STAGE_TIMEOUTS` (complete map including recon_validation / threat_modeling / sca* / ci_export / dedup_stage). Nested nuclei/validation/active_scan/`_tool_runner` **skip** second `authorize()` when `ctx.execution_ticket` is set (stage admit is the only reserve+consume). Standalone tool entry still authorizes once. HMAC has **no** published fallback string; missing env key → process-local random (verify dies across restart). SettlementIntent carries `budget_reservation_id` from the stage ticket (F-033 I28↔I31).

### Settle Outcome Decision Table

| Stage Attempt Outcome | WAL Result | Settle Status | `FINDING_CREATED` Emitted? | I28 Budget Action | Stage Terminal Status |
|---|---|---|---|---|---|
| **COMPLETED (with findings)** | Committed (`wal_id` assigned) | `COMMITTED` | **Yes** (strict I31) | `COMMIT` (Consumed += units) | `COMPLETED` |
| **COMPLETED (zero findings)** | Committed (`wal_id` assigned) | `COMMITTED` | No | `RELEASE` (Available += units) | `COMPLETED` |
| **FAILED / ERROR** | Recorded (`wal_id` assigned) | `REJECTED` | No | `RELEASE` (Available += units) | `FAILED` / `DEGRADED` |
| **EGRESS_VIOLATION** | Rejected / Refused | `DROPPED` | No | `RELEASE` (Available += units) | `FAILED` |
| **SKIPPED / UNBUDGETED** | Not submitted to WAL | `N/A` | No | `RELEASE` (if reserved) | `SKIPPED_DISABLED` |

---

## F-006 — Leases, time & global budget

Source: [architecture.md](architecture.md) I19/I28, [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md), `src/decision/hunt_budget.py`, `src/core/frontier/lease_status.py`. Absorbed F-011, F-038.

```mermaid
flowchart TD
    subgraph ClockModel["Multi-Clock Model (F-038)"]
        HLC["Hybrid Logical Clock (HLC)"]:::impl --> EventOrder["Scan Journal Ordering I23"]:::impl
        Mono["time.monotonic()"]:::impl --> LeaseTTL["Sublease & Fence Expiration (Zero Skew Drift)"]:::impl
        Wall["time.time() (UTC)"]:::impl --> AuditTime["Audit Logs & SIEM Export (I22 < 1000ms Bound)"]:::impl
    end

    subgraph LeaseFSM["Lease State Machine & Compensation (I19, I20, I21)"]
        Reserve["ReserveGlobalBudget"]:::impl --> RESERVED["RESERVED (Outstanding)"]:::impl
        RESERVED -->|"allocate / dispatch"| ACTIVE["ACTIVE (Outstanding)"]:::impl
        RESERVED -->|"expire (timeout via Mono)"| EXPIRED["EXPIRED (Available)"]:::impl
        RESERVED -->|"compensate (abort/failure)"| COMPENSATED["COMPENSATED (Available)"]:::impl
        RESERVED -->|"settle consumed"| CONSUMED["CONSUMED (Committed)"]:::impl
        ACTIVE -->|"settle consumed > 0"| CONSUMED
        ACTIVE -->|"expire (TTL elapsed via Mono)"| EXPIRED
        EXPIRED -->|"compensate (late reconciliation)"| COMPENSATED
        CONSUMED -->|"idempotent re-settle"| CONSUMED
        COMPENSATED -->|"idempotent no-op"| COMPENSATED
    end
```

`Total = Consumed + Outstanding + Available`. Slabs add `SlabReserved` (I26). COMPENSATED only from RESERVED or EXPIRED. EXPIRED is **not** in `TERMINAL` (it can still compensate). `SETTLEMENT_PENDING` is a legacy alias of ACTIVE, not a written state. I30 ticket **consume is not** an I28 budget commit — only settle (`BudgetProjection` COMMIT/RELEASE, including stage settle) moves RESERVED → CONSUMED / COMPENSATED. Adaptive scan reserve→commit mirrors settle when no stage ticket path is used.

### Budget Delta & Accounting Matrix

Universal Conservation Equation: $$\text{TotalBudget} \equiv \text{Consumed} + \text{Outstanding} + \text{Available}$$

| Transition | $\Delta\text{Consumed}$ | $\Delta\text{Outstanding (Reserved+Active)}$ | $\Delta\text{Available}$ | Trigger / Precondition |
|---|---|---|---|---|
| `Genesis` $\rightarrow$ `RESERVED` | $0$ | $+\text{units}$ | $-\text{units}$ | `HuntBudget.reserve_with_identity` (ticket issued) |
| `RESERVED` $\rightarrow$ `ACTIVE` | $0$ | $0$ | $0$ | Subprocess dispatch (in-flight execution) |
| `ACTIVE` $\rightarrow$ `CONSUMED` | $+\text{units}$ | $-\text{units}$ | $0$ | Stage `COMPLETED` committed with findings at WAL |
| `ACTIVE` $\rightarrow$ `COMPENSATED` / `EXPIRED` | $0$ | $-\text{units}$ | $+\text{units}$ | Stage `FAILED` / `SKIPPED` / TTL expired |
| `RESERVED` $\rightarrow$ `COMPENSATED` | $0$ | $-\text{units}$ | $+\text{units}$ | Pre-dispatch cancellation or authorization rejection |
| *Late Settle after EXPIRED* | $0$ | $0$ | $0$ | **Refused**: requires prior compensation check |

---

## F-007 — Application state machines & lifecycle coupling

Source: `src/jobs/status.py`, `src/core/models/stage_status.py`, `src/core/contracts/finding_lifecycle.py`, `src/jobs/run_outcome.py`. Absorbed F-008, F-027.

```mermaid
flowchart TD
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
        SP --> SDG["DEGRADED (Terminal)"]:::impl
        SP --> SC["COMPLETED (Terminal)"]:::impl
        SP --> SF["FAILED (Terminal)"]:::impl
        SP --> SSF["SKIPPED_FAILED (Terminal)"]:::impl
        SR --> SC
        SR --> SDG
        SR --> SF
        SR --> SSD
        SR --> SSF
        SF --> SR
        SF --> SC
        SF --> SDG
        SF --> SSF
    end
    subgraph Finding["Finding Lifecycle & Tri-Axial Model"]
        FC["CANDIDATE (Surface)"]:::impl --> FR["REPORTABLE (Surface)"]:::impl
        FC --> FF["FALSE_POSITIVE (Surface Sticky)"]:::impl
        FC -.->|"Confidence Refinement"| FV["VALIDATED / EXPLOITABLE"]:::impl
        FV --> FR
        FV --> FF
        FR -->|"Analyst Triage"| FF
    end
    SC & SDG & SF & SSD & SSF --> Coupling["derive_job_and_exit (Total Mapping Lattice)"]:::impl
    FR & FF --> Coupling
    Coupling --> JP
```

### Finding Tri-Axial State Model

1. **Surface Lifecycle Axis** (`FindingLifecycleState`): `CANDIDATE` $\rightarrow$ `REPORTABLE` $\mid$ `FALSE_POSITIVE`.
2. **Confidence / Exploitability Axis**: `heuristic_candidate` $\rightarrow$ `passive_only` $\rightarrow$ `validated` $\rightarrow$ `exploitable`.
3. **Operator Ticket Axis** (`FindingTicketStatus`): `OPEN` $\rightarrow$ `CLOSED` (orthogonal to surface lifecycle).

---

## F-009 — Resilience: breaker, QoS, PID & bulkhead

Source: [architecture.md](architecture.md), [performance.md](performance.md), `src/infrastructure/resilience/`, `src/realtime/prioritized_broker.py`, `src/realtime/qos_admit.py`. Absorbed F-024, F-030.

```mermaid
flowchart TD
    Load["Target Probe Latency & Error Rate"]:::impl --> PID["AdaptivePIDController (Concurrency Tuning)"]:::impl
    PID --> Conc["Dynamic Concurrency Window"]:::impl
    Load --> Bulk["BulkheadPool (Per-Host Host Isolation)"]:::impl
    Load --> Bloom["NeuralBloomFilter (Fast Evasion Deduplication)"]:::impl
    Fail["Consecutive Probe Failures (>= 5)"]:::impl --> CLOSED
    subgraph CB["Circuit Breaker (Per-Target)"]
        CLOSED["CLOSED (Normal Traffic)"]:::impl -->|"Failures >= Threshold"| OPEN["OPEN (Tripped / Shedding)"]:::forbidden
        OPEN -->|"Cooldown Elapsed (20s)"| HALF_OPEN["HALF_OPEN (Trial Generation N)"]:::impl
        HALF_OPEN -->|"Trial Probe OK"| CLOSED
        HALF_OPEN -->|"Trial Probe Failed"| OPEN
    end
    OPEN -->|"set_reserve_gate"| NoTicket["HuntBudget Gate: Reserve Blocked"]:::impl
    Evt["TelemetryEvent Stream"]:::impl --> Q{"qos_admit"}:::impl
    Q -->|P0: Critical Audit| P0["P0: In-Memory Spool + Disk Journal (p0_capacity=1000)"]:::impl
    Q -->|P1: Stage Lifecycle| P1["P1: Reliable Queue Dispatch"]:::impl
    Q -->|P2: Findings Buffer| P2["P2: Coalesced Findings Stream"]:::impl
    Q -->|P3: Periodic Metrics| P3["P3: 1s Rolling Aggregates"]:::impl
    Q -->|P4: Debug Traces| P4["P4: Lowest Priority / First Shed"]:::impl
```

### Telemetry QoS Shedding Decision Matrix (`qos_admit.py`)

| Resource Condition | P0 (Critical Audit) | P1 (Stage Events) | P2 (Findings) | P3 (1s Aggregates) | P4 (Debug Traces) |
|---|---|---|---|---|---|
| **Normal (< 85% Disk, < 80% RAM)** | `Admit` (Durable) | `Admit` | `Admit` | `Admit` | `Admit` |
| **Moderate (>= 85% Disk / CPU > 90%)** | `Admit` (Durable) | `Admit` | `Admit` | `Admit` | **`DROP`** |
| **Severe (>= 92% Disk / RAM > 90%)** | `Admit` (Spool) | `Admit` | **`COALESCE`** | **`DROP`** | **`DROP`** |
| **Spool Saturated (> 1000 P0 items)** | `Backpressure` (Block caller) | `Drop` | `Drop` | `Drop` | `Drop` |

---

## F-018 — Failure decision tree, concurrency & I35 recovery

Source: [FAILURE_MODES.md](FAILURE_MODES.md), `src/core/frontier/failure_model.py` (I34), `src/core/frontier/recovery_protocol.py` (I35), `src/jobs/run_outcome.py`, `src/infrastructure/task_pool/run_lock.py`. Absorbed F-039.

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
    subgraph Concurrency["Concurrency & Run Locking (F-039)"]
        ScanReq["cstp scan run target"]:::impl --> Acquire{"Acquire RunLock (Target Name)"}:::impl
        Acquire -->|Collision| CollisionExit["Exit 1 (Lock Collision Error)"]:::forbidden
        Acquire -->|Acquired| Run["Pipeline Execution"]:::impl
        Run --> ReleaseLock["Release RunLock on Exit"]:::impl
    end

    Run --> Precedence{"derive_job_and_exit"}:::impl
    Precedence -->|Cancel Signal| Exit130["Exit 130: STOPPED"]:::impl
    Precedence -->|Fatal Stage / No Output / I35 FAIL_CLOSED| Exit3["Exit 3: FAILED (Infra Failure)"]:::impl
    Precedence -->|Policy Violation| Exit2["Exit 2: COMPLETED (Policy Violation)"]:::impl
    Precedence -->|Degraded Probes| Exit4["Exit 4: COMPLETED (Partial Run)"]:::impl
    Precedence -->|Clean Run| Exit0["Exit 0: COMPLETED (Clean / Pass)"]:::impl
    
    subgraph ErrorMap["Runtime Failure Mappings"]
        CB["Circuit Breaker OPEN"]:::forbidden -->|"HTTP 429 / Throttle"| Exit4
        WAL["WALCorruptionError I15"]:::forbidden -->|"Unrecoverable"| Exit3
        Pol["Policy Gate (No Log)"]:::forbidden -->|"Fail-Closed"| Exit2
        Egress["EgressViolationError I29"]:::forbidden -->|"Scope Guard"| Exit3
        CollisionExit --> Exit1["Exit 1: FAILED"]:::impl
    end
```

### I34 Formal Failure Recovery Semantics

| Failure Domain | Retry | Rollback | Compensate | Fail-Closed | Authoritative Resolution |
|---|---|---|---|---|---|
| **WAL Corruption** | No | No | No | **Yes** | Restore from last verified FSM snapshot |
| **Authority Loss** | No | No | No | **Yes** | Await leader election or restart in quorum-1 mode |
| **Replication Divergence** | No | No | No | **Yes** | Restore local FSM from leader PartitionWAL |
| **Event Delivery Failure** | **Yes** | No | No | No | Replay outbox dispatch by `DeliveryId` (I32) |
| **Budget Inconsistency** | No | No | **Yes** | **Yes** | Compensate outstanding I28 reservations |
| **FSM Invariant Violation** | No | No | No | **Yes** | Snapshot re-baseline plus sequential WAL replay |
| **Egress Policy Violation** | No | No | **Yes** | **Yes** | Terminate subprocess; release reserved requests |
| **RunLock Collision** | No | No | No | **Yes** | Abort execution (Exit 1: Target under active scan) |

```mermaid
flowchart TD
    U["UNINITIALIZED"]:::impl --> LS["LOAD_SNAPSHOT"]:::impl
    U --> LW0["LOAD_WAL"]:::impl
    U --> Fresh["FRESH"]:::impl
    LS --> VS["VERIFY_SNAPSHOT"]:::impl
    VS -->|"partition plane unread schema"| Closed["FAIL_CLOSED"]:::forbidden
    VS -->|"frontier snapshot unread schema"| Fresh
    VS --> LW["LOAD_WAL"]:::impl
    LW0 --> Rec
    LW --> Rec["RECONCILE_SNAPSHOT_WAL"]:::impl
    Rec -->|"snapshot ahead / truncated partition"| Closed
    Rec -->|"behind or semantically old"| Replay["REPLAY_WAL"]:::impl
    Rec -->|"truncated frontier"| Stale["STALE snapshot then REPLAY_WAL"]:::impl
    Stale --> Replay
    Replay --> FSMR["RECONSTRUCT_FSM (Partition Plane Only)"]:::impl
    FSMR --> Out["RECONCILE_OUTBOX"]:::impl
    Out -->|"FSM without outbox"| Rebuild["Rebuild by EventId"]:::impl
    Out -->|"outbox without FSM"| Orphan["Ignore Orphan Rows"]:::vacuous
    Rebuild & Orphan --> Del["RECONCILE_DELIVERY"]:::vacuous
    Del -->|"delivery ahead"| Drop["Discard Extra DeliveryIds"]:::vacuous
    Del -->|"delivery missing"| ReplayD["Replay Dispatch I32"]:::vacuous
    Drop & ReplayD --> Inv["VERIFY_INVARIANTS (I30–I33 Check)"]:::impl
    Inv -->|"compensation crash: valid lease"| Comp["Idempotent I28 Replay"]:::impl
    Inv -->|"compensation crash: uncompensatable"| Closed
    Inv -->|"prerequisite invariant failed"| Closed
    Inv -->|"invariants verified"| Ready["READY"]:::impl
    Comp --> Ready
```

PartitionWAL is never reconstructed. VERIFY_INVARIANTS fail-closes if recovered tickets/settlements violate I30–I33 (`invariant_graph.py`). Checkpoint and DeliveryLedger are caches. Crash between WAL commit and outbox append is the rebuild path; crash during compensation is I28 idempotent.

`RecoveryManager._execute_verdict` runs rebuild_outbox. Checkpoint/WAL tickets and settlements are collected into I35 `VERIFY_INVARIANTS` (empty sets are a no-op — live checkpoints usually have no `tickets`/`settlements` keys). `delivered_event_ids` on the scan observation are empty by design; `replay_delivery` is a log line. FAIL_CLOSED sets `execute_stages=False` and CLI returns exit 3 (not a dry-run 0). After attach, `apply_authority_recovery` walks the PARTITION plane. `derive_job_and_exit` is the strictly total lattice for CLI exit and dashboard reap with defined total priority order (130 > 3 > 7 > 2 > 4 > 1 > 0) and unified `no_pipeline_output` handling. A non-fatal FAILED producer unblocks reporting; only `fatal_stages` trigger exit 3.

---

## F-019 — Operator surface, multi-tenancy & telemetry

Source: [frontend.md](frontend.md), [api-reference.md](api-reference.md), [OBSERVABILITY_CATALOG.md](OBSERVABILITY_CATALOG.md), `src/telemetry/normalizer.ts`, `src/dashboard/fastapi/middleware.py`. Absorbed F-023, F-026, F-031, F-043.

```mermaid
flowchart TD
    subgraph MultiTenant["Multi-Tenant Isolation & Auth (F-043)"]
        HTTP["Inbound HTTP Request"]:::impl --> Tenant["X-Tenant-ID Header Extraction"]:::impl
        Tenant --> Auth{"Auth Mode Verification"}:::impl
        Auth -->|"Bearer / API Key"| ScopeSigned["Tenant-Scoped Ticket Signed"]:::impl
        Auth -->|"Session Cookie (Mutating)"| CSRF{"CSRF Token Valid?"}:::impl
        CSRF -->|No| R403["403 Forbidden"]:::forbidden
        CSRF -->|Yes| ScopeSigned
        ScopeSigned --> TenantStorage["Partitioned Storage & Budget Allocation"]:::impl
        ScopeSigned --> Dispatch["FastAPI Route Handlers"]:::impl
    end

    Dispatch --> Hook["useJobMonitor (React Hook)"]:::impl
    Hook --> REST["REST /api/jobs/:id"]:::impl
    Hook --> SSE["SSE /api/jobs/:id/progress/stream"]:::impl
    Hook --> WS["WebSocket /ws/logs/:id"]:::impl
    Hook --> Triage["WebSocket /ws/triage/:run_id"]:::impl
    REST & SSE & WS --> Norm["telemetry/normalizer.ts"]:::impl
    WS -->|Drop| REST
    Norm --> Stores["Zustand Stores"]:::impl
    Stores --> Pages["Jobs / Findings / Cockpit UI"]:::impl
    
    subgraph OutboxNotify["Outbox & Telemetry Pipeline"]
        Settle["Settlement COMMITTED"]:::impl --> Outbox["L2 DurableOutbox"]:::impl
        Outbox --> LiveBus["event_bus.EventBus (In-Process Dispatch)"]:::impl
        LiveBus --> Fan["Fan-Out (Cap 5)"]:::impl
        LiveBus -.->|"Delivery Fail ≠ Uncommit I32"| Settle
        App["Pipeline + Dashboard"]:::impl --> Prom["Prometheus Metrics (:9090)"]:::impl
        App --> Logs["JSON Logs + HMAC Audit"]:::impl
        Prom --> Graf["Grafana Dashboard"]:::impl
    end
```

SSE is `GET /api/jobs/{id}/progress/stream` (not `/progress/stream`). Logs WS is `/ws/logs/{job_id}`. Triage WS `/ws/triage/{run_id}` is live and uncharted before this row. Origin validation runs before the `DASHBOARD_AUTH_DISABLED` admin bypass.

---

## F-020 — Tests, CI shards & quality policy gates

Source: [testing.md](testing.md), [ci-cd-integration.md](ci-cd-integration.md), `.github/workflows/ci.yml`, `src/jobs/run_outcome.py`. Absorbed F-045.

```mermaid
flowchart TD
    subgraph CI_Pipeline["GitHub Actions CI Pipeline (.github/workflows/ci.yml)"]
        Push["Push to main / PR"]:::impl --> Lint["ruff + format + Bandit HIGH"]:::impl
        Push --> Mypy["mypy typecheck"]:::impl
        Push --> TS["typescript tsc --noEmit"]:::impl
        Push --> FE["frontend build"]:::impl
        Push --> Shards["pytest shards (test matrix, fail-fast false)"]:::impl
        Push --> Audit["security-audit"]:::impl
        Push --> Scan["security-scan Semgrep p/ci"]:::impl
        Push --> Hard["hardening check"]:::impl
        Push --> Iac["iac-scan Checkov yaml"]:::impl
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
        PolicyGate -->|Critical >= Max Allowed| FailExit["Exit 2: Policy Violation (Block Merge)"]:::forbidden
        PolicyGate -->|Within Thresholds| PassExit["Exit 0: Clean Pass (Export SARIF)"]:::impl
    end
```

Per-test timeout 20s (`pytest-timeout`). Do not CI-fail on k8s `REPLACE_WITH_*`. Fail-fast recon tests stay skipped.

---

## F-022 — Gap-analysis status

Source: [GAP_ANALYSIS.md](GAP_ANALYSIS.md)

```mermaid
flowchart LR
    Raft["Raft transport"] --> Impl["Implemented single-node"]
    Tickets["Jira ServiceNow DefectDojo"] --> Impl
    Policy["Policy via Raft commands"] --> Impl
    Ghost["Multi-host Ghost migration"] --> Open["Open / single-node"]
    WASM["WASM AEVE"] --> Flag["Feature Flagged"]
    PPO["PPO / DRL"] --> Heur["Heuristic stub"]
    GNN["GNN attack graph"] --> Dijk["Dijkstra LIBRARY"]
```

---

## F-025 — Non-authoritative planes, caches & multi-tier storage

Source: [architecture/cache-unification.md](architecture/cache-unification.md), [environment-variables.md](environment-variables.md), [architecture.md](architecture.md) §7.17, `src/infrastructure/cache/`, `src/pipeline/maintenance.py`. Absorbed F-028, F-032, F-041.

```mermaid
flowchart TD
    subgraph Config["Three config trees — do not unify"]
        ScanCfg["ValidatedPipelineConfig JSON"]:::impl
        DashCfg["DashboardConfig DASHBOARD_*"]:::impl
        QueueCfg["QueueConfig QUEUE_*"]:::impl
        ScanCfg -.-> NoGod["no kernel / God-container"]:::forbidden
        DashCfg -.-> NoGod
        QueueCfg -.-> NoGod
    end

    subgraph MultiTierCache["Multi-Tier Cache & Storage Hierarchy (F-041)"]
        Call["Cache Read Request"]:::impl --> SF["Single-Flight In-Memory LRU (L1)"]:::impl
        SF -->|Hit| Return["Return Cached Output"]:::impl
        SF -->|Miss| Persist["SQLite cache_layer.db / Redis (L2)"]:::impl
        Persist -->|Miss| Origin["Stage Execution (Compute)"]:::impl
        Origin --> Write["Write-Through to L1 & L2"]:::impl
        Done["Completed Scan Run"]:::impl --> Hot["Hot NVMe Storage (output/run_id/)"]:::impl
        Hot --> Index["index_runs Metadata"]:::impl
        Hot --> PruneCheck{"Older than 14 Days?"}:::impl
        PruneCheck -->|Yes| Arch["Gzip Compressed Archive Tier"]:::impl
        Arch --> PruneJob["cstp system cleanup (Pruning)"]:::impl
    end
```

---

## F-033 — Global invariants I1–I37 proof graph & registry

Source: `src/core/frontier/invariant_graph.py`, `src/core/frontier/global_invariants.py`, `src/core/frontier/causal_identity.py`, `src/core/frontier/event_delivery.py`.

### Formal System Invariant Registry (I1–I37)

| Invariant | Formal Statement | Owning Chart | Enforcing Module | Primary Test Suite | Status |
|---|---|---|---|---|---|
| **I1** | Deterministic virtual partition placement ($H \pmod{1024}$) | F-002 | `global_coordination.py` | `test_region_model.py` | `impl` |
| **I2** | Single leader per partition ($L_p \le 1$) | F-002 | `consensus.py` | `test_distributed_invariants.py` | `impl` |
| **I3** | Monotonic lease terms ($T_{k+1} > T_k$) | F-002 | `consensus.py` | `test_distributed_invariants.py` | `impl` |
| **I4** | Quorum commitment majority ($N/2 + 1$) | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `single-node` |
| **I5** | Universal budget conservation ($\text{Total} \equiv \text{Consumed} + \text{Outstanding} + \text{Available}$) | F-006 | `global_coordination.py` | `test_formal_invariants.py` | `impl` |
| **I6** | Integer non-negative allocations | F-006 | `global_coordination.py` | `test_formal_invariants.py` | `impl` |
| **I7** | Single global authority for budget ($P-0000$) | F-002 | `global_coordination.py` | `test_formal_invariants.py` | `impl` |
| **I8** | FSM determinism across sequential replay | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `impl` |
| **I9** | Zero I/O inside FSM Apply transition | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `impl` |
| **I10** | Monotonically increasing applied index | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `impl` |
| **I11** | PartitionWAL total order per partition | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `impl` |
| **I12** | CRC-64 verification on WAL record read | F-003 | `wal.py` | `test_wal.py` | `impl` |
| **I13** | HMAC cryptographic command receipt signing | F-003 | `receipt_crypto.py` | `test_atlas_holes.py` | `impl` |
| **I14** | Durable outbox append before external dispatch | F-003 | `outbox.py` | `test_eventbus_guarantees.py` | `impl` |
| **I15** | Crash-safe disk flush before commit acknowledgement | F-003 | `wal.py` | `test_wal.py` | `impl` |
| **I16** | FSM snapshot point-in-time consistency | F-018 | `recovery/manager.py` | `test_recovery_manager.py` | `impl` |
| **I17** | Single leader-home authority placement | F-002 | `region_model.py` | `test_region_model.py` | `impl` |
| **I18** | Replicated journal filter (commands dropped on peer relay) | F-002 | `replication.py` | `test_region_model.py` | `impl` |
| **I19** | Strict lease lifecycle ($\text{RESERVED} \rightarrow \text{ACTIVE} \rightarrow \text{CONSUMED}$) | F-006 | `lease_status.py` | `test_lease_status.py` | `impl` |
| **I20** | Idempotent terminal lease compensation | F-006 | `lease_status.py` | `test_lease_status.py` | `impl` |
| **I21** | Forbidden direct `ACTIVE` $\rightarrow$ `COMPENSATED` transition | F-006 | `lease_status.py` | `test_lease_status.py` | `impl` |
| **I22** | Max 1000ms clock skew admission gate | F-003 | `replicated_log.py` | `test_formal_invariants.py` | `impl` |
| **I23** | Monotonic logical timestamp ordering | F-003 | `state.py` | `test_state_crdt.py` | `impl` |
| **I24** | Bounded tombstone retention compaction | F-003 | `state.py` | `test_state_crdt.py` | `impl` |
| **I25** | CRDT convergence under commutative merge | F-003 | `state.py` | `test_state_crdt.py` | `impl` |
| **I26** | Multi-Raft quota slab conservation | F-006 | `global_coordination.py` | `test_formal_invariants.py` | `impl` |
| **I27** | Bounded per-host bulkhead concurrency | F-009 | `infrastructure/` | `test_resilience.py` | `impl` |
| **I28** | Settle-only budget commit & integer conservation | F-006 | `hunt_budget.py` | `test_global_invariants.py` | `impl` |
| **I29** | Pre-flight & continuous egress scope enforcement | F-004 | `process_sandbox.py` | `test_sandbox.py` | `impl` |
| **I30** | Cryptographic quartet ticket binding | F-033 | `authorization.py` | `test_global_invariants.py` | `impl` |
| **I31** | Settlement-gated `FINDING_CREATED` emission | F-033 | `event_bus.py` | `test_global_invariants.py` | `impl` |
| **I32** | Non-authoritative EventBus outbox decoupling | F-033 | `event_bus.py` | `test_eventbus_guarantees.py` | `impl` |
| **I33** | Causal identity chain ($\text{CommandId} \rightarrow \dots \rightarrow \text{DeliveryId}$) | F-033 | `causal_identity.py` | `test_causal_identity.py` | `impl` |
| **I34** | Formal failure recovery boundaries (11 domains) | F-018 | `failure_model.py` | `test_failure_model.py` | `impl` |
| **I35** | Dual-plane deterministic recovery state machine | F-018 | `recovery_protocol.py` | `test_recovery_protocol.py` | `impl` |
| **I36** | Single-writer regions & journal-only relay | F-002 | `region_model.py` | `test_region_model.py` | `impl` |
| **I37** | Zero dual-writer fenced authority transfer | F-002 | `authority_transfer.py` | `test_authority_transfer.py` | `impl` |

```mermaid
flowchart TD
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
        Durable -->|"yes"| Finding["FINDING_CREATED Allowed"]:::impl
        Durable -->|"no"| NoEmit["EventBus Refuses Finding"]:::forbidden
        Finding --> Outbox["DurableOutboxLedger"]:::impl
        Outbox --> Bus["EventBus (In-Process Dispatch)"]:::impl
        Bus --> Consumers["Observers / UI"]:::impl
        Outbox -->|Append Fail| NoBus["No Bus Notification; Replay Later"]:::vacuous
    end
    
    subgraph ProofGraph["Invariant Dependency & Proof Graph"]
        I22["I22 Clock Admission"]:::impl --> I30g["I30 Ticket Binding"]:::impl
        I30g -->|"Every authorized execution gets causal IDs"| I33g["I33 Causal Identity"]:::impl
        I30g --> I28g["I28 Settle-Only Budget"]:::impl
        I33g --> I31g["I31 Settlement"]:::impl
        I28g -->|"Settle cannot consume outside reservation"| I31g
        I31g -->|"Only COMMITTED WAL may emit"| I32g["I32 Durable Outbox"]:::impl
        I32g --> I34g["I34 Failure Semantics"]:::impl
        I28g --> I34g
        I34g --> I35g["I35 Recovery Protocol"]:::impl
        I32g -->|"Recovery rebuilds delivery from durable state"| I35g
        I35g -->|"READY before regional ownership"| I36g["I36 Single-Writer Region"]:::impl
        I36g -->|"Transfer only via fence"| I37g["I37 Transfer Fence"]:::impl
        I30g --> I37g
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
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | Observability | OpenTelemetry OTLP collector gRPC endpoint |
| `AUTHORITY_SIGNING_KEY_ID` | `authority-hmac-v1` | Frontier Crypto | Key identifier for HMAC receipt verification |

---

## Changelog

| Date | Milestone / Change Description | Kind |
|---|---|---|
| 2026-08-26 | Unified Architecture Specification (consolidated 13 core survivor charts F-001–F-033, merged F-034–F-045, grounded formal I1–I37 invariant registry) | active |

Append a row for every later edit. Do not delete this table.
