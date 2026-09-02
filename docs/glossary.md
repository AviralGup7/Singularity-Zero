# Glossary

Key terms for Singularity-Zero. Architecture contract: [architecture.md](architecture.md). Charts: [flowchart.md](flowchart.md).

## Dual log (do not unify)

- **FrontierWAL**: Live **scan journal** (F-004). `settle_stage_output` writes `SettlementIntent` here. CRC skip-unless-high-corruption is intentional for this journal.
- **PartitionWAL**: Raft **authority plane** (F-003). Fail-closed on CRC (`WALCorruptionError`). CLI is quorum-1. `NetworkRaftTransport` is LIBRARY.
- **EventBus**: In-process notification dispatcher after the durable outbox (I32). Not a log. `src/core/events/bus.py` is UNUSED (perfection suite).

## Authority & tickets

- **P-0000**: Global coordination partition for budget, placement, policy watermark. Ticket `partition_id` default is `"P-0000"` (not `"P0"`).
- **AuthorizedExecutionTicket (I30)**: Binds scope_token_hash, budget_reservation_id, authority_revision, command_id. `authorize` requires `reserve_with_identity`. `consume_ticket` checks the reservation, I37 live revision, then `commit_requests(1)`.
- **SettlementIntent (I31)**: Durable claim. `FINDING_CREATED` only after COMMITTED + nonempty `wal_id` + HMAC receipt. A failed stage still settles; settle **status** is `REJECTED` (wal_id present; no finding event).
- **I33 identity chain**: `CommandId → ExecutionId → AttemptId → SettlementId → WalId → EventId → DeliveryId`. FAILED attempt does not close `execution_id`.
- **I35 recovery protocol**: State machine in `recovery_protocol.py`. Empty recovered ticket/settlement sets are a no-op. `delivered_event_ids` on the scan observation are empty by design.
- **I36 region**: Placement/replica boundary, not a second authority. `assert_lease_settle_colocated`. Live CLI home is `local`.
- **I37 fence**: `OWNED → FENCED → OWNED`. `initiate_transfer` is tests-only on the scan path. Fenced placement refuses reserve and `settle_stage_output`.
- **Proof graph**: `src/core/frontier/invariant_graph.py`. Bidirectional edges + reverse assumptions. I35 VERIFY consults it.

## Leases (I28)

- States: RESERVED, ACTIVE, CONSUMED, EXPIRED, COMPENSATED.
- **TERMINAL** = CONSUMED | COMPENSATED. **EXPIRED is not terminal** (`EXPIRED → COMPENSATED` is legal).
- `RESERVED → CONSUMED` without ACTIVE is legal (F-006 mermaid).
- `SETTLEMENT_PENDING` is a legacy alias of ACTIVE.

## Jobs & stages

- **JobStatus** (`src/jobs/status.py`): lowercase. `_transition` is the only writer. PENDING↛STOPPING. Terminal COMPLETED/FAILED/STOPPED cannot leave.
- **derive_job_and_exit**: 0/2 COMPLETED, 4 COMPLETED+degraded, 1/3 FAILED, 130/7 STOPPED. Not total: scheduler 1/7/130, lock 1, fatal recon 3 bypass it.
- **Stage CAS** (`stage_status.py`): illegal COMPLETED→FAILED / COMPLETED→SKIPPED* / SKIPPED*→COMPLETED **raises**. FAILED→COMPLETED and FAILED→SKIPPED_FAILED are legal (I33 retry).
- **force_fresh**: dashboard default True — UI never resumes unless false.

## Findings

- Surface: CANDIDATE | REPORTABLE | FALSE_POSITIVE. `detected` aliases CANDIDATE.
- **`"open"` is not a lifecycle alias** — it is `FindingTicketStatus` / `ticket_status`.
- PDF uses `filter_report_surface` (`surface == REPORTABLE`).
- CRDT: `findings` vs `candidates` LWW-sets. Identity key is `event_id` (else `settlement_id:seq`). Do not mutate dicts to inject `id`.

## Other

- **Circuit breaker**: CLOSED → OPEN → HALF_OPEN. One async HALF_OPEN probe; `_trial_generation` increments on enter HALF_OPEN. OPEN stops new HuntBudget reserves (`set_reserve_gate`).
- **qos_admit(event, disk_pct)**: admit | coalesce | drop. ≥85 DROP P4; ≥92 DROP P3/P4, COALESCE P1/P2.
- **CRDT / HLC**: LWW-Sets keyed by Hybrid Logical Clocks. `tick()` / `update(remote)` must not mix `time.time()` into monotonic.
- **Ghost-Actor / Ghost-VFS**: In-process + gossip handoff, not a running multi-host migrator. Encrypted RAM isolation is Python `bytearray` ([architecture.md](architecture.md) §7.13).
- **CSI**: Composite Severity Index 0–10 ([architecture.md](architecture.md) §7.11).
- **WAL trim**: never drop ids newer than `last_wal_id`.
- **HMAC key**: `AUTHORITY_SIGNING_KEY` then `APP_SECRET_KEY` then process-local random. No published fallback.

## Frontend

- Default theme: dark / `night-city`.
- SSE: `/api/jobs/{id}/progress/stream`. WS: `/ws/logs/{job_id}`, `/ws/triage/{run_id}`.
- 3D cockpit: [architecture.md](architecture.md) §7.18, [frontend.md](frontend.md).
