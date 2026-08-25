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

## Atlas Index

Live charts only. Retired ids are one-line headings after the last live chart (never reuse).

| Id | Chart | Source |
|---|---|---|
| F-001 | Documentation portal map | [index.md](index.md) |
| F-002 | System topology and regions | [architecture-overview.md](architecture-overview.md), [multi-region.md](multi-region.md) |
| F-003 | Authority plane | [architecture.md](architecture.md), [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md) |
| F-004 | Live scan path | [architecture.md](architecture.md), [codebase.md](codebase.md), [commands.md](commands.md) |
| F-006 | Leases and global budget | [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md) |
| F-007 | Application state machines | `src/jobs/status.py`, `stage_status.py`, `finding_lifecycle.py` |
| F-009 | Resilience: breaker, QoS, PID | [architecture.md](architecture.md), [performance.md](performance.md) |
| F-018 | Failure-mode decision tree and recovery model | [FAILURE_MODES.md](FAILURE_MODES.md), `src/core/frontier/failure_model.py` |
| F-019 | Operator surface | [frontend.md](frontend.md), [api-reference.md](api-reference.md), [OBSERVABILITY_CATALOG.md](OBSERVABILITY_CATALOG.md) |
| F-020 | Tests and CI shards | [testing.md](testing.md) |
| F-022 | Gap-analysis status | [GAP_ANALYSIS.md](GAP_ANALYSIS.md) |
| F-025 | Non-authoritative planes | [architecture/cache-unification.md](architecture/cache-unification.md), [environment-variables.md](environment-variables.md) |
| F-033 | Global invariants I30–I33 | `src/core/frontier/global_invariants.py`, `causal_identity.py`, `event_delivery.py` |

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
    Arch --> ExecReq["architecture/execution-request-contract.md"]
    Arch --> CacheDoc["architecture/cache-unification.md"]
```

---

## F-002 — System topology and regions

Source: [architecture-overview.md](architecture-overview.md), [multi-region.md](multi-region.md). Absorbed F-021.

```mermaid
flowchart TD
    UI["React 19 dashboard"] <-->|"HTTP REST / WebSocket"| API["FastAPI dashboard"]
    API -->|"enqueue / control"| Orch["Pipeline orchestrator"]
    Orch --> Engines["Recon / Analysis / Fuzz / Exploit"]
    Orch --> State["WAL / CRDT / Cache / Mesh"]
    Engines --> Sinks["Learning + Reporting"]
    State --> Sinks
    subgraph RegionA["Region A"]
        GA["Gossip A"]
        OA["Authority + FrontierWAL"]
        RA["Redis stream"]
        OA --> RA
    end
    subgraph RegionB["Region B"]
        GB["Gossip B"]
        OB["Authority + FrontierWAL"]
        RB["Redis stream"]
        OB --> RB
    end
    State --- OA
    GA <-->|"SWIM UDP AES-256-GCM"| GB
    RA <-->|"WALReplicationRelay"| RB
```

## F-003 — Authority plane

Source: [architecture.md](architecture.md), [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md). Absorbed F-012, F-014, F-016.

```mermaid
flowchart TD
    Typed["TypedCommand.to_envelope"] --> Up["SchemaUpcaster on load"]
    Up --> Admit["Admission clock-skew I22"]
    Admit --> Log["ReplicatedPartitionLog"]
    subgraph Raft["L0 Raft commit"]
        Leader["Leader PartitionWAL"]
        F1["Follower WAL"]
        Leader -->|"AppendEntries"| F1
        F1 -->|"ACK quorum 1 live"| Leader
        Leader --> Commit["Advance commitIndex"]
    end
    Log --> Leader
    Commit --> Apply["L1 FSM.Apply zero I/O"]
    Apply --> Receipt["HMAC CommandReceipt"]
    Apply --> Outbox["L2 DurableOutbox"]
    Outbox --> Proj["L3 projections"]
    Proj --> Cache["L4 caches / telemetry"]
    Cache --> UI["L5 presentation"]
    UI -.->|"must never author L0-L3"| Forbidden["Forbidden as source of truth"]
    Tuner["Policy tuner"] --> Gate["PolicyGovernanceGate"]
    Gate -->|no log| Closed["Fail-closed"]
    Gate -->|log attached| Promo["Promote / RollbackPolicy"]
    Promo --> Apply
```

Live CLI is single-node quorum-1. `NetworkRaftTransport` stays LIBRARY.

## F-004 — Live scan path

Source: [architecture.md](architecture.md), [codebase.md](codebase.md), [commands.md](commands.md), [architecture/execution-request-contract.md](architecture/execution-request-contract.md). Absorbed F-005, F-010, F-013, F-015, F-017, F-029.

```mermaid
flowchart TD
    CSTP["cstp"] --> Launch["launch dashboard + worker"]
    CSTP --> Scan["scan run"]
    CSTP --> Sys["system doctor / status / setup"]
    Scan --> Runtime["src.pipeline.runtime"]
    Runtime --> Bind["register_process_bindings"]
    Bind --> Recover["RecoveryManager: snapshot + WAL journal"]
    Recover --> Verify["verify_checkpoint_against_fsm"]
    Recover --> Auth["attach_pipeline_authority"]
    Auth --> Stamp["ctx.budget_enforcer + authorizer"]
    Stamp --> DAG
    subgraph DAG["STAGE_GRAPH spine"]
        Scope["scope"] --> Sub["subdomains"]
        Sub --> LiveH["live_hosts"]
        LiveH --> Urls["urls"]
        Urls --> Params["parameters"]
        Params --> Rank["ranking"]
        Rank --> Passive["passive / analysis"]
        Rank --> Nuclei["nuclei"]
        Rank --> Active["active_scan"]
        Passive --> Val["validation"]
        Nuclei --> Val
        Active --> Val
        Val --> Merge["merge"]
        Merge --> Report["reporting"]
    end
    DAG --> Req["ExecutionRequest + ScopeToken"]
    Req --> Budget{"HuntBudget reserve"}
    Budget -->|exhausted| Rej["ScopeAuthorizationError"]
    Budget -->|ok| Ticket["AuthorizedExecutionTicket I30 binds scope+reservation+revision+command"]
    Ticket --> SB["ProcessSandbox I29 metadata-guard"]
    SB -->|out of scope| Viol["EgressViolationError"]
    SB --> Out["StageOutput / RawExecutionClaim"]
    Out --> Coord["SettlementCoordinator 5-stage"]
    Coord --> Thaw["_to_mutable"]
    Thaw --> WAL["append SettlementIntent"]
    WAL -->|COMMITTED + wal_id I31| Outbox["DurableOutbox FINDING_CREATED"]
    Outbox --> Emit["EventBus notify I32"]
    WAL -->|REJECTED / DEDUPLICATED / no wal_id| Silent["no FINDING_CREATED"]
```

## F-005 — RETIRED → F-004

## F-006 — Leases and global budget

Source: [architecture.md](architecture.md) I19/I28, [FORMAL_COMMAND_SPECIFICATION.md](FORMAL_COMMAND_SPECIFICATION.md). Absorbed F-011.

```mermaid
flowchart TD
    Reserve["ReserveGlobalBudget"] --> RESERVED
    RESERVED -->|"allocate"| ACTIVE
    RESERVED -->|"expire"| EXPIRED
    RESERVED -->|"compensate"| COMPENSATED
    RESERVED -->|"settle consumed"| CONSUMED
    ACTIVE -->|"settle consumed greater than 0"| CONSUMED
    ACTIVE -->|"expire"| EXPIRED
    EXPIRED -->|"compensate"| COMPENSATED
    CONSUMED -->|"idempotent"| CONSUMED
    COMPENSATED -->|"idempotent no-op"| COMPENSATED
    Total["TotalBudget I5"] --> Cons["Consumed"]
    Total --> Outs["Outstanding RESERVED+ACTIVE"]
    Total --> Avail["Available"]
    Reserve --> Outs
    CONSUMED --> Cons
    COMPENSATED --> Avail
    EXPIRED --> Avail
```

`Total = Consumed + Outstanding + Available`. Slabs add `SlabReserved` (I26). COMPENSATED only from RESERVED or EXPIRED.

## F-007 — Application state machines

Source: `src/jobs/status.py`, `src/core/models/stage_status.py`, `src/core/contracts/finding_lifecycle.py`. Absorbed F-008, F-027.

```mermaid
flowchart TD
    subgraph Job["JobStatus — only _transition writes"]
        JP["PENDING"] --> JS["STARTING"]
        JS --> JR["RUNNING"]
        JR --> JX["STOPPING"]
        JX --> JD["STOPPED"]
        JR --> JC["COMPLETED"]
        JR --> JF["FAILED"]
        JC --> JTerm["terminal"]
        JF --> JTerm
        JD --> JTerm
    end
    subgraph Stage["Stage CAS"]
        SP["PENDING"] --> SR["RUNNING"]
        SP --> SSD["SKIPPED_DISABLED"]
        SP --> SDG["DEGRADED"]
        SR --> SC["COMPLETED"]
        SR --> SDG
        SR --> SF["FAILED"]
        SR --> SSF["SKIPPED_FAILED"]
    end
    subgraph Finding["Finding lifecycle — REPORTABLE and FP sticky"]
        FC["CANDIDATE"] --> FR["REPORTABLE"]
        FC --> FF["FALSE_POSITIVE"]
        FR --> FR
        FF --> FF
        FC -.-> FV["VALIDATED / EXPLOITABLE refine CANDIDATE"]
        FV --> FR
        FV --> FF
    end
    Job --> Stage
    Stage --> Finding
```

Illegal stage: COMPLETED→FAILED, COMPLETED→SKIPPED*, FAILED→COMPLETED, SKIPPED*→COMPLETED.

Finding surface is CANDIDATE | REPORTABLE | FALSE_POSITIVE. `detected` aliases CANDIDATE. Dashboard `open/closed` is a different axis (ticket status), not this SM.

## F-008 — RETIRED → F-007

## F-009 — Resilience: breaker, QoS, PID

Source: [architecture.md](architecture.md), [performance.md](performance.md). Absorbed F-024, F-030.

```mermaid
flowchart TD
    Load["Probe load"] --> PID["AdaptivePIDController"]
    PID --> Conc["concurrency"]
    Load --> Bulk["BulkheadPool per host"]
    Load --> Bloom["NeuralBloomFilter"]
    Fail["consecutive failures"] --> CB
    subgraph CB["Circuit breaker"]
        CLOSED -->|"trip"| OPEN
        OPEN -->|"cooldown"| HALF_OPEN
        HALF_OPEN -->|"trial ok"| CLOSED
        HALF_OPEN -->|"trial fail"| OPEN
    end
    Evt["TelemetryEvent"] --> Q{"qos"}
    Q -->|P0| P0["memory then disk spool"]
    Q -->|P1| P1["reliable lifecycle"]
    Q -->|P2| P2["coalesce findings"]
    Q -->|P3| P3["1s aggregates"]
    Q -->|P4| P4["drop first"]
    Disk{"disk percent"} -->|85| P4
    Disk -->|92| P3
```

One async HALF_OPEN probe; `_trial_generation` increments on enter HALF_OPEN.

## F-010 — RETIRED → F-004

## F-011 — RETIRED → F-006

## F-012 — RETIRED → F-003

## F-013 — RETIRED → F-004

## F-014 — RETIRED → F-003

## F-015 — RETIRED → F-004

## F-016 — RETIRED → F-003

## F-017 — RETIRED → F-004

## F-018 — Failure-mode decision tree and recovery model

Source: [FAILURE_MODES.md](FAILURE_MODES.md), `src/core/frontier/failure_model.py` (I34).

Exit codes answer "what result did this scan produce?". The recovery table answers "what is the system allowed to do?" for each class. Exotic multi-node repair is not implemented; the outcome is still named.

```mermaid
flowchart TD
    Run["Scan finished"] --> Q1{"Stage status?"}
    Q1 -->|FAILED| Infra["Exit 3 infrastructure / target down"]
    Q1 -->|POLICY_VIOLATION| Vuln["Exit 2 findings exceed policy"]
    Q1 -->|COMPLETED| Q2{"Finding count?"}
    Q2 -->|greater than 0| Report["Report findings"]
    Q2 -->|0| Q3{"degraded_probes or warnings?"}
    Q3 -->|no| Clean["Exit 0 genuine clean target"]
    Q3 -->|yes| Deg["Exit 4 degraded run"]
    Run --> CB["Circuit OPEN HTTP 429"]
    Run --> WAL["WALCorruptionError I15 fail-closed"]
    Run --> Pol["Policy gate fail-closed without log"]
    Run --> Egress["EgressViolationError I29"]
    Run --> Lease["Illegal lease transition I28"]
```

```mermaid
flowchart TD
    subgraph Table["I34 recovery semantics"]
        WALC["WAL corruption"] --> WALP["Retry no / Rollback no / Compensate no / Fail-closed yes / restore snapshot"]
        AUTH["Authority loss"] --> AUTHP["Retry no / Rollback no / Compensate no / Fail-closed yes / wait for leader or restart quorum-1"]
        DIV["Replication divergence"] --> DIVP["Retry no / Rollback no / Compensate no / Fail-closed yes / restore FSM from leader WAL"]
        BUS["Event delivery failure"] --> BUSP["Retry yes / Rollback no / Compensate no / Fail-closed no / replay dispatch by DeliveryId"]
        BUD["Budget inconsistency"] --> BUDP["Retry no / Rollback no / Compensate yes / Fail-closed yes / compensate outstanding I28"]
        FSM["FSM invariant violation"] --> FSMP["Retry no / Rollback no / Compensate no / Fail-closed yes / snapshot plus sequential replay"]
    end
```

---

## F-019 — Operator surface

Source: [frontend.md](frontend.md), [api-reference.md](api-reference.md), [OBSERVABILITY_CATALOG.md](OBSERVABILITY_CATALOG.md). Absorbed F-023, F-026, F-031.

```mermaid
flowchart TD
    HTTP["Inbound HTTP"] --> Tenant["X-Tenant-ID"]
    Tenant --> Auth{"auth mode"}
    Auth -->|"Bearer / API key"| Dispatch["route handler"]
    Auth -->|"session cookie mutating"| CSRF{"CSRF ok?"}
    CSRF -->|no| R403["403"]
    CSRF -->|yes| Dispatch
    Dispatch --> Hook["useJobMonitor"]
    Hook --> REST["REST /api/jobs/:id"]
    Hook --> SSE["SSE /progress/stream"]
    Hook --> WS["WebSocket /ws/logs"]
    REST --> Norm["normalizer"]
    SSE --> Norm
    WS --> Norm
    WS -->|drop| REST
    Norm --> Stores["Zustand stores"]
    Stores --> Pages["Jobs / Findings / Cockpit"]
    Settle["Settlement COMMITTED"] --> Outbox["L2 DurableOutbox"]
    Outbox --> LiveBus["event_bus.EventBus in-process notify"]
    LiveBus --> Fan["fan-out cap 5"]
    LiveBus -.->|"delivery fail ≠ uncommit I32"| Settle
    Unused["events.bus UNUSED"] --> PerfSuite["perfection suite only"]
    App["pipeline + dashboard"] --> Prom["Prometheus"]
    App --> Logs["JSON logs + HMAC audit"]
    Prom --> Graf["Grafana"]
```

## F-020 — Tests and CI shards

Source: [testing.md](testing.md)

```mermaid
flowchart TD
    Push["Push to main"] --> Lint["ruff + format + Bandit"]
    Push --> Mypy["mypy"]
    Push --> TS["typescript"]
    Push --> FE["frontend"]
    Push --> Shards["pytest shards"]
    Shards --> Infra["unit-infra"]
    Shards --> Core["unit-core"]
    Shards --> Pipe["unit-pipeline"]
    Shards --> Recon["unit-recon"]
    Shards --> Analysis["unit-analysis"]
    Shards --> Dash["unit-dashboard"]
    Shards --> Exploit["unit-exploit"]
    Shards --> App["unit-app"]
    Shards --> Suites["suites architecture"]
    Shards --> Cov["coverage fail_under 45"]
    Local["Local agents"] --> Small["only smallest relevant slice less than or equal 50s"]
```

---

## F-021 — RETIRED → F-002

## F-022 — Gap-analysis status

Source: [GAP_ANALYSIS.md](GAP_ANALYSIS.md)

```mermaid
flowchart LR
    Raft["Raft transport"] --> Impl["Implemented single-node"]
    Tickets["Jira ServiceNow DefectDojo"] --> Impl
    Policy["Policy via Raft commands"] --> Impl
    Ghost["Multi-host Ghost migration"] --> Open["Open / single-node"]
    WASM["WASM AEVE"] --> Flag["Feature flagged"]
    PPO["PPO / DRL"] --> Heur["Heuristic stub"]
    GNN["GNN attack graph"] --> Dijk["Dijkstra LIBRARY"]
```

---

## F-023 — RETIRED → F-019

## F-024 — RETIRED → F-009

## F-025 — Non-authoritative planes

Source: [architecture/cache-unification.md](architecture/cache-unification.md), [environment-variables.md](environment-variables.md), [architecture.md](architecture.md) §7.17. Absorbed F-028, F-032.

```mermaid
flowchart TD
    subgraph Config["Three config trees — do not unify"]
        ScanCfg["ValidatedPipelineConfig JSON"]
        DashCfg["DashboardConfig DASHBOARD_*"]
        QueueCfg["QueueConfig QUEUE_*"]
        ScanCfg -.-> NoGod["no kernel / God-container"]
        DashCfg -.-> NoGod
        QueueCfg -.-> NoGod
    end
    Call["cache get"] --> SF["single-flight"]
    SF --> Mem["LRU"]
    Mem -->|miss| Persist["SQLite or Redis"]
    Persist -->|miss| Origin["compute"]
    Origin --> Write["write-through"]
    Done["Completed run"] --> Hot["hot NVMe"]
    Hot --> Arch["gzip archive"]
    Hot --> Prune{"older than 14d?"}
    Prune -->|yes| Drop["prune_hot_tier"]
    Arch --> Index["index_runs"]
    Hot --> Index
```

## F-026 — RETIRED → F-019

## F-027 — RETIRED → F-007

## F-028 — RETIRED → F-025

## F-029 — RETIRED → F-004

## F-030 — RETIRED → F-009

## F-031 — RETIRED → F-019

## F-032 — RETIRED → F-025

## F-033 — Global invariants I30–I33

Source: `src/core/frontier/global_invariants.py`, `src/core/frontier/causal_identity.py`, `src/core/frontier/event_delivery.py`.

EventBus is an **in-process notification dispatcher**, not a durable log and not a source of truth. Authoritative Event → Durable Outbox → Delivery Dispatcher → EventBus → consumers. `EventBus.emit(FINDING_CREATED)` without `wal_id` + `authoritative=True` is refused.

I33 makes replay/retry/dedup proveable: child ids are derived from parents; a FAILED attempt does not close the execution; EventBus DeliveryId is skipped on crash-replay.

```mermaid
flowchart TD
    subgraph I30["I30 authorization causality"]
        Scope["ScopeToken hash"]
        Res["BudgetReservation id in enforcer ledger"]
        Rev["AuthorityRevision"]
        Cmd["CommandId from reserve_with_identity"]
        Scope --> Ticket["AuthorizedExecutionTicket"]
        Res --> Ticket
        Rev --> Ticket
        Cmd --> Ticket
        Ticket -->|"missing binding or unknown reservation"| Reject["no ticket / consume False"]
    end
    subgraph I33["I33 causal identity chain"]
        Cmd --> ExecId["ExecutionId"]
        ExecId --> AttId["AttemptId retry n"]
        AttId --> StlId["SettlementId"]
        StlId --> WalId["WalId"]
        WalId --> EvtId["EventId"]
        EvtId --> DlvId["DeliveryId"]
        AttId -->|"same attempt"| Same["identical reconstructed ids"]
        AttId -->|"new attempt after FAILED"| Retry["new SettlementId"]
    end
    subgraph I31["I31 settlement causality"]
        Intent["SettlementIntent"] --> Durable["WAL wal_id COMMITTED"]
        Durable -->|"yes"| Finding["FINDING_CREATED allowed"]
        Durable -->|"no"| NoEmit["EventBus refuses finding"]
    end
    subgraph I32["I32 EventBus is not authority"]
        Finding --> Outbox["DurableOutbox append by EventId"]
        Outbox --> Bus["EventBus in-process notify by DeliveryId"]
        Bus --> Consumers["observers"]
        Bus -.->|"handler/outbox fail"| Still["authoritative state unchanged"]
        DlvId -->|"already delivered"| Skip["skip emit"]
    end
```

## Changelog

| Date | Change | Kind |
|---|---|---|
| 2026-08-25 | F-001–F-030 created | add |
| 2026-08-25 | F-001/F-008 edit; F-031 F-032 added | edit |
| 2026-08-25 | Merged into 11 survivors; retired absorbed ids | edit |
| 2026-08-25 | Compacted retired headings and changelog (live charts unchanged) | edit |
| 2026-08-25 | F-033: fail-closed I30 ledger + EventBus refuse unauthoritative FINDING_CREATED | edit |
| 2026-08-25 | F-033: I33 CommandId→DeliveryId chain after code landed | edit |
| 2026-08-25 | F-018: I34 recovery model next to the exit-code tree | edit |
| 2026-08-26 | F-007: CANDIDATE is the finding surface start state | edit |
| 2026-08-26 | F-019: Norm is frontend/src/telemetry/normalizer.ts | edit |

Append a row for every later edit. Do not delete this table.
