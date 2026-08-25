# Failure Modes & Diagnostics Handbook

This document provides a comprehensive operational guide for identifying, diagnosing, and triaging pipeline failure modes, circuit breaker trip conditions, and differentiating genuine "zero finding" scans from degraded scan states.

Exit codes (the table below) answer **what result this scan produced**. I34 recovery semantics answer **what the system is allowed to do** for each class of failure. The machine-readable table is `src/core/frontier/failure_model.py`.

## I34 Recovery Model

Exotic multi-node repair is **not** implemented. The architecture still names the outcome so operators and code cannot invent a forbidden action.

| Failure class | Retry | Rollback | Compensate | Fail-closed | Operator action |
|---|---|---|---|---|---|
| **WAL corruption** (I15) | No | No | No | Yes | Restore certified snapshot or discard corrupt uncommitted tail. Never skip-and-continue on PartitionWAL/outbox. |
| **Authority loss** (I17) | No | No | No | Yes | Refuse mutations until a leader exists. Single-node quorum-1: restart so `start_election()` self-elects. Do not panic-compensate leases. |
| **Replication divergence** (I11) | No | No | No | Yes | Halt the divergent replica. Restore FSM from leader PartitionWAL + sequential replay (I16). |
| **Event delivery failure** (I32) | Yes | No | No | No | None. Outbox keeps EventId; DeliveryId is not recorded on failure, so dispatch replay is safe. Settlement stays COMMITTED. |
| **Budget inconsistency** (I5) | No | No | Yes | Yes | Stop new reservations. Compensate outstanding RESERVED/EXPIRED subleases (I28). Do not invent budget units. |
| **FSM invariant violation** (I9/I16) | No | No | No | Yes | Stop `FSM.Apply`. Restore from certified snapshot + sequential WAL replay. Do not patch in-memory FSM. |

Why WAL compensate is **No**: I15 never applied the corrupt record, so there is nothing to compensate. Why authority-loss compensate is **No**: outstanding leases expire or compensate through I28 on a live leader, not on step-down.

## I35 Recovery Protocol

I34 answers "what may this *failure class* do?". I35 answers the crash questions for every *persistent object*. The machine-readable protocol is `src/core/frontier/recovery_protocol.py`. Exotic multi-node repair is still not implemented; the outcome is still named.

Recovery is a state machine, not another table:

`UNINITIALIZED → LOAD_SNAPSHOT → VERIFY_SNAPSHOT → LOAD_WAL → RECONCILE_SNAPSHOT_WAL → REPLAY_WAL → RECONSTRUCT_FSM → RECONCILE_OUTBOX → RECONCILE_DELIVERY → VERIFY_INVARIANTS → READY | FAIL_CLOSED | FRESH`

| Durable object | Authoritative source | Reconstructible from | Deterministic | Idempotent |
|---|---|---|---|---|
| PartitionWAL | itself (L0, CRC fail-closed) | not reconstructible | Yes | Yes |
| PartitionFSM | PartitionWAL committed entries | sequential `FSM.Apply` (I16) | Yes | Yes |
| FrontierWAL | itself (scan journal) | not reconstructible | Yes | Yes |
| Checkpoint snapshot | none — L3 cache | FrontierWAL + PartitionWAL | Yes | Yes |
| DurableOutbox | committed `emitted_events` | WAL rebuild by EventId | Yes | Yes |
| DeliveryLedger | none — process-local cache | empty; replay dispatch | Yes | Yes |
| GlobalBudget | P-0000 budget commands | sequential reserve/settle/expire | Yes | Yes |
| SettlementIntent | FrontierWAL envelope (`wal_id`) | journal replay (I31/I33) | Yes | Yes |
| Policy state | PartitionFSM policy commands | promote/rollback replay | Yes | Yes |

| Crash / disagreement | Partition plane | Frontier / scan journal |
|---|---|---|
| Snapshot ahead of WAL | Fail-closed | Discard snapshot; keep journal |
| Snapshot behind WAL / semantically old | Replay exclusive tail | Replay exclusive tail |
| WAL truncated after snapshot | Fail-closed | Keep snapshot as STALE; do not invent ids |
| Schema newer than reader | Fail-closed | Fresh run |
| Schema older than reader | Forward-migrate | Forward-migrate |
| Outbox without FSM | Ignore orphan outbox rows | Ignore orphan outbox rows |
| FSM / WAL committed, outbox missing | Rebuild outbox from committed events | Rebuild outbox |
| Delivery ahead of outbox | Discard extra DeliveryIds | Discard extra DeliveryIds |
| Outbox appended, delivery missing | Replay dispatch (I32) | Replay dispatch |
| Crash during compensation | Idempotent replay of I28 | Idempotent replay of I28 |

---

## 🎯 Findings vs. Silent Gaps

In automated security testing, distinguishing between a secure target and a degraded scan where tools failed silently is critical:

| Stage Status | Finding Count | Exit Code | Diagnostic Signature | Interpretation |
|---|---|---|---|---|
| **COMPLETED** | `0` | `0` | No degraded probes or unhandled errors | **Genuine Clean Target**: Target scanned successfully; no vulnerabilities detected. |
| **FAILED** | `0` | `3` | Fatal recon failure or target unreachable | **Infrastructure Failure**: Target offline or network path blocked. |
| **COMPLETED** | `0` | `4` | `degraded_probes` or `warnings` present | **Degraded Run**: Specific probes timed out or were blocked by target WAF. |
| **POLICY_VIOLATION** | `> 0` | `2` | Findings exceed `policy.toml` thresholds | **Vulnerabilities Found**: Exploits or vulnerabilities confirmed. |

---

## 🔍 Detailed Breakdown of Common Failure Modes

### 1. Reconnaissance Yields Zero URLs
- **Symptom**: Reconnaissance stage finishes with `0` discovered URLs; active scanning terminates immediately.
- **Root Cause**: Target domain does not resolve, DNS rate limits triggered, or target scope is misconfigured.
- **Remediation**: Check domain resolution (`nslookup <target>`) and verify `configs/scope.txt`.

### 2. Circuit Breaker Trips to OPEN (HTTP 429 Throttling)
- **Symptom**: Log contains `CircuitBreaker: OPEN (rate limit detected)` and active probing pauses.
- **Root Cause**: Target server or reverse proxy is rate limiting requests.
- **Remediation**: The orchestrator automatically extracts `Retry-After` headers and pauses stage workers. To prevent re-occurrence, lower probe concurrency in `configs/config.json`.

### 3. Exploit PoC Sandbox Execution Timeout
- **Symptom**: Finding verification stage flags candidate finding as `UNVERIFIED_TIMEOUT`.
- **Root Cause**: The validation script exceeded its allotted WASM / subprocess execution time quota.
- **Remediation**: Increase the validation timeout in `config.json` under `validation_timeout_seconds` or inspect the PoC script for infinite loops.

### 4. ML Severity Active Learning Degradation
- **Symptom**: Severity predictions fallback to static baseline or standard logistic regression.
- **Root Cause**: Compiled machine learning dependencies (`xgboost`, `scikit-learn`) unavailable in runtime environment.
- **Remediation**: The system automatically utilizes pure-NumPy fallback routines (`src/learning/`) ensuring inference continuity without crashing.

### 5. Partition WAL Corruption (`WALCorruptionError` - Invariant I15)
- **Symptom**: Log coordinator crashes on startup with `WALCorruptionError: CRC-64 mismatch in PartitionWAL ...`.
- **Root Cause**: Incomplete flush, partial disk write, or external modification of physical `.aof` WAL records.
- **Remediation**: In accordance with fail-closed invariant I15, corrupt WAL segments are never partially applied. Restore from the latest certified snapshot (`CertifiedSnapshot`) or discard the corrupt uncommitted tail after verifying integrity.

### 6. Policy Governance Gate Fail-Closed Rejection
- **Symptom**: `PolicyGovernanceGate` returns `False` / `None` and logs `Policy promotion rejected: no authoritative replicated log (fail-closed)`.
- **Root Cause**: Attempting to promote or roll back an adaptive DRL policy in standalone mode without an active `replicated_log` Raft authority attached.
- **Remediation**: Ensure `PipelineAuthorityRuntime` is attached to the orchestrator or provide an initialized `ReplicatedPartitionLog` instance to the gate.

### 7. Process Sandbox Egress Boundary Violation (Invariant I29)
- **Symptom**: Exploit validation fails with `EgressViolationError: Destination host ... violates scope boundary`.
- **Root Cause**: Tool subprocess attempted to open network sockets to disallowed external hosts or internal cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`).
- **Remediation**: Verify the `ScopeToken` allowed domains configuration. Subprocess egress to non-whitelisted destinations is strictly blocked by design.

### 8. Illegal Lease Transition Rejection (Invariant I28)
- **Symptom**: `ValueError: Illegal lease transition (I28): <src> -> <dst>` or compensation failure.
- **Root Cause**: A worker or saga attempted an out-of-order state change (e.g. attempting to compensate an already `CONSUMED` lease or transitioning from `CONSUMED` back to `ACTIVE`).
- **Remediation**: Inspect execution sequence. Sub-lease compensations are only allowed from `RESERVED` or `EXPIRED` states. Duplicate compensations are automatically handled as idempotent no-ops.

### 9. HMAC Command Receipt Verification Failure (Invariant I13)
- **Symptom**: `verify_receipt_signature()` returns `False` or receipt validation fails during audit.
- **Root Cause**: Mismatched `AUTHORITY_SIGNING_KEY` / `APP_SECRET_KEY` between cluster nodes, or tampered receipt payload attributes.
- **Remediation**: Ensure all cluster nodes share the identical `AUTHORITY_SIGNING_KEY` and `AUTHORITY_SIGNING_KEY_ID` environment variables.