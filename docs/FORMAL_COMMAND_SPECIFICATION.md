# Formal Command & State Transition Specification

This document defines the **Formal Command & State Transition Contract** for all operations in the Cyber Security Test Pipeline. Canonical architecture: [architecture.md](architecture.md).

---

## 1. Command Specification Matrix

### 1.1 `ReserveGlobalBudgetCommand`
- **Authority Partition**: `P-0000` (Global Coordination)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-res-01",
    "run_id": "R-101",
    "partition_id": "P-0412",
    "units": 2500,
    "expected_aggregate_version": 12
  }
  ```
- **FSM Read-Set**: `GlobalBudgetAggregate(P-0000)` (`available`, `consumed`, `outstanding_reserved`, `version`).
- **Preconditions**:
  1. `units > 0`
  2. `available >= units`
  3. `expected_aggregate_version == GlobalBudgetAggregate.version`
- **Deterministic State Transition**:
  - $\text{available}' = \text{available} - \text{units}$
  - $\text{outstanding\_reserved}' = \text{outstanding\_reserved} + \text{units}$
  - `subleases[sublease_id] = GlobalSubLease(status="RESERVED", units=units)`
  - $\text{version}' = \text{version} + 1$
- **Emitted Domain Event**: `GlobalSubLeaseReservedEvent(run_id, partition_id, sublease_id, units)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="SUBLEASE_RESERVED")`
- **Failure Modes**:
  - `INSUFFICIENT_GLOBAL_BUDGET`: `available < units` $\rightarrow$ `REJECTED`, $\Delta \text{version} = 0$. (`reserve_sublease` returns this exact code.)
  - `NON_POSITIVE_UNITS`: `units <= 0` $\rightarrow$ `REJECTED`.
  - `VERSION_CONFLICT`: version mismatch $\rightarrow$ `REJECTED`, $\Delta \text{version} = 0$.
- **Replay Behavior**: Re-evaluating against committed log reproduces identical `available` and `outstanding_reserved` quantities.

---

### 1.2 `AllocateSubLeaseCommand`
- **Authority Partition**: Target Partition ($P_x$, e.g., `P-0412`)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-alloc-01",
    "sublease_id": "sublease_R101_P0412",
    "run_id": "R-101",
    "units_allocated": 2500,
    "expected_aggregate_version": null
  }
  ```
- **FSM Read-Set**: `PartitionFSM[Px].subleases`
- **Preconditions**:
  1. `sublease_id` not already present with different allocation
  2. `units_allocated > 0`
- **Deterministic State Transition**:
  - `subleases[sublease_id] = SubLeaseRecord(status="ACTIVE", allocated=units, consumed=0)`
  - $\text{aggregate\_version}' = \text{aggregate\_version} + 1$
- **Emitted Domain Event**: `SubLeaseAllocatedEvent(sublease_id, units_allocated, run_id)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="SUBLEASE_ALLOCATED")`
- **Failure Modes**:
  - `DUPLICATE_SUBLEASE_CONFLICT`: existing sub-lease has conflicting allocation $\rightarrow$ `REJECTED`.

---

### 1.3 `AuthorizeExecutionCommand`
- **Authority Partition**: Target Partition ($P_x$)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-auth-01",
    "aggregate_id": "exec-9941",
    "capability_id": "cap-018f",
    "sublease_id": "sublease_R101_P0412",
    "units_requested": 5,
    "key_epoch": 1,
    "expected_aggregate_version": 0
  }
  ```
- **FSM Read-Set**: `subleases[sublease_id]`, `revocation_registry`, `key_revocation_epoch`.
- **Preconditions**:
  1. `key_epoch >= PartitionFSM.key_revocation_epoch`
  2. `sublease.units_consumed + units_requested <= sublease.units_allocated`
  3. `aggregate_id` does not exist (initial version == 0)
- **Deterministic State Transition**:
  - `aggregates[exec-9941] = AggregateState(status="RUNNING", units_reserved=5, expires_at=optional, version=1)`
  - $\text{aggregate\_version}' = 1$
- **Emitted Domain Event**: `ExecutionAuthorizedEvent(exec_id, capability_id, sublease_id, units_reserved)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="EXECUTION_AUTHORIZED")`
- **Failure Modes**:
  - `KEY_REVOKED`: `key_epoch < key_revocation_epoch` $\rightarrow$ `REJECTED`.
  - `INSUFFICIENT_SUBLEASE_BALANCE`: allocation exceeded $\rightarrow$ `REJECTED`.

---

### 1.4 `SubmitExecutionClaim`
- **Authority Partition**: Target Partition ($P_x$)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-claim-01",
    "aggregate_id": "exec-9941",
    "capability_id": "cap-018f",
    "units_consumed": 3,
    "findings": [{"title": "SQL Injection", "severity": "high"}],
    "expected_aggregate_version": 1
  }
  ```
- **FSM Read-Set**: `aggregates[exec-9941]`, `revocation_registry`, `subleases[sublease_id]`.
- **Preconditions**:
  1. `aggregate.status == "RUNNING"`
  2. `capability_id not in revocation_registry`
  3. `expected_aggregate_version == aggregate.version`
- **Deterministic State Transition**:
  - `unused_refund = max(0, units_reserved - units_consumed)`
  - `subleases[sublease_id].units_consumed += units_consumed`
  - `subleases[sublease_id].status = CONSUMED` if fully consumed, else `ACTIVE` (`SETTLEMENT_PENDING` is a legacy alias of ACTIVE, not written)
  - `aggregates[exec-9941].status = "SETTLED"`
  - $\text{aggregate\_version}' = \text{aggregate\_version} + 1$
- **Emitted Domain Event**: `ExecutionClaimSettledEvent(exec_id, units_consumed, unused_refund, findings_count)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="CLAIM_SETTLED_SUCCESS")`
- **Failure Modes**:
  - `EXECUTION_NOT_RUNNING`: `status != RUNNING` $\rightarrow$ `REJECTED`.
  - `CAPABILITY_REVOKED`: `cap_id in revocation_registry` $\rightarrow$ `REJECTED`.

---

### 1.5 `SettlementReturnCommand`
- **Authority Partition**: `P-0000` (Global Coordination)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-return-01",
    "sublease_id": "sublease_R101_P0412",
    "units_consumed": 3,
    "units_returned": 2
  }
  ```
- **FSM Read-Set**: `GlobalBudgetAggregate(P-0000)` (`subleases[sublease_id]`, `consumed`, `available`).
- **Preconditions**:
  1. `sublease_id in subleases`
  2. `sublease.status in ("RESERVED", "ACTIVE")` (or normalized legacy aliases)
- **Deterministic State Transition**:
  - $\text{consumed}' = \text{consumed} + \text{units\_consumed}$
  - $\text{available}' = \text{available} + \text{units\_returned}$
  - `subleases[sublease_id].status = "CONSUMED"`
  - $\text{version}' = \text{version} + 1$
- **Universal Invariant Verification**:
  $$\Delta \text{TotalBudget} = \Delta \text{Consumed} + \Delta \text{OutstandingReserved} + \Delta \text{Available} = 3 - 5 + 2 = 0$$
- **Emitted Domain Event**: `SubLeaseReconciledEvent(sublease_id, units_consumed, units_returned)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="SUBLEASE_CONSUMED")`

---

### 1.6 `LeaseTimeoutCommand`
- **Authority Partition**: Target Partition ($P_x$)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-timeout-01",
    "aggregate_id": "exec-9941",
    "payload": {
      "observed_at": 1770000000.0,
      "max_skew": 0.5
    },
    "expected_aggregate_version": 1
  }
  ```
- **Preconditions**:
  1. `aggregate.status == "RUNNING"`
  2. `expires_at > 0` (stored on authorize; unset leases cannot time out)
  3. `observed_at >= expires_at + max_skew`
- **Failure Modes**:
  - `EXECUTION_NOT_RUNNING`: aggregate missing or not RUNNING $\rightarrow$ `NO_OP`.
  - `NOT_YET_EXPIRED`: `expires_at <= 0` or `observed_at < expires_at + max_skew` $\rightarrow$ `REJECTED`.
- **Deterministic State Transition**:
  - `aggregates[exec-9941].status = "EXPIRED"`
  - `pessimistic_consumed = reserved_units; pessimistic_refund = 0`
  - $\text{aggregate\_version}' = \text{aggregate\_version} + 1$
- **Emitted Domain Event**: `LeaseExpiredEvent(exec_id, consumed_forfeit, refund=0)`

---

### 1.7 `PromotePolicyCommand`
- **Authority Partition**: Target Partition ($P_x$ or `P-0000`)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-promote-01",
    "command_type": "PromotePolicyCommand",
    "aggregate_id": "policy_active",
    "payload": {
      "policy_id": "policy_v2_alpha",
      "artifact_hash": "sha256_hash_abc123",
      "policy_version": "v2.0",
      "parent_policy_id": "policy_v1_base"
    },
    "expected_aggregate_version": 0
  }
  ```
- **FSM Read-Set**: `PartitionFSM.aggregates["policy_active"]`
- **Preconditions**:
  1. `policy_id` is non-empty string.
  2. `artifact_hash` corresponds to validated external artifact.
- **Deterministic State Transition**:
  - `aggregates["policy_active"] = PolicyAggregate(active_policy_id=policy_id, artifact_hash=artifact_hash, status="ACTIVE")`
  - $\text{aggregate\_version}' = \text{aggregate\_version} + 1$
- **Emitted Domain Event**: `PolicyPromotedEvent(policy_id, artifact_hash, policy_version)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="POLICY_PROMOTED")`

---

### 1.8 `RollbackPolicyCommand`
- **Authority Partition**: Target Partition ($P_x$ or `P-0000`)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-rollback-01",
    "command_type": "RollbackPolicyCommand",
    "aggregate_id": "policy_active",
    "payload": {
      "parent_policy_id": "policy_v1_base"
    },
    "expected_aggregate_version": 1
  }
  ```
- **Preconditions**:
  1. Valid `parent_policy_id` exists in current policy state payload or command payload.
- **Deterministic State Transition**:
  - `aggregates["policy_active"].state_payload["active_policy_id"] = parent_policy_id`
  - `aggregates["policy_active"].status = "ACTIVE"` (restored parent is the live policy)
  - `aggregates["policy_active"].state_payload["status"] = "ROLLED_BACK"` (transition record only)
  - $\text{aggregate\_version}' = \text{aggregate\_version} + 1$
- **Emitted Domain Event**: `PolicyRolledBackEvent(active_policy_id=parent_policy_id)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="POLICY_ROLLED_BACK")`

---

### 1.9 `ExpireSubLeaseCommand`
- **Authority Partition**: `P-0000` (Global Coordination)
- **Input Schema**:
  ```json
  {
    "command_id": "cmd-expire-sl-01",
    "sublease_id": "sublease_R101_P0412",
    "units_consumed": 0
  }
  ```
- **Preconditions**:
  1. `sublease_id in subleases` and `sublease.status in ("RESERVED", "ACTIVE")` (legacy `ISSUED` normalizes to `RESERVED`).
- **Deterministic State Transition**:
  - `units_returned = sublease.units_allocated - units_consumed`
  - $\text{consumed}' = \text{consumed} + \text{units\_consumed}$
  - $\text{available}' = \text{available} + \text{units\_returned}$
  - `subleases[sublease_id].status = "EXPIRED"`
  - $\text{version}' = \text{version} + 1$
- **Universal Invariant Verification (INVARIANT-001 & INVARIANT-005)**:
  $$\Delta \text{TotalBudget} \equiv \Delta \text{Consumed} + \Delta \text{OutstandingReserved} + \Delta \text{Available} = 0$$

---

### 1.10 Typed Formal Command Constructors (`src/core/frontier/commands.py`)

To prevent runtime schema divergence and hand-crafted payload dictionaries, typed command constructors wrap `TypedCommand` and export to standard `CommandEnvelope` instances:

| Constructor | Envelope Command Type | Aggregate ID | Target Partition | Primary Parameters |
|---|---|---|---|---|
| `reserve_global_budget(...)` | `ReserveGlobalBudgetCommand` | `"global_budget"` | `P-0000` | `run_id`, `partition_id`, `units`, `sublease_id` |
| `allocate_sublease(...)` | `AllocateSubLeaseCommand` | `sublease_id` | $P_x$ | `sublease_id`, `run_id`, `units_allocated`, `partition_id` |
| `settlement_return(...)` | `SettlementReturnCommand` | `"global_budget"` | `P-0000` | `sublease_id`, `units_consumed`, `units_returned` |
| `promote_policy(...)` | `PromotePolicyCommand` | `"policy_active"` | `P-0000` / $P_x$ | `policy_id`, `artifact_hash`, `policy_version`, `parent_policy_id`, `generation` |
| `rollback_policy(...)` | `RollbackPolicyCommand` | `"policy_active"` | `P-0000` / $P_x$ | `parent_policy_id`, `target_generation` |

---

### 1.11 Canonical Lease Lifecycle & Invariant I28 (`src/core/frontier/lease_status.py`)

All sub-leases follow a finite state machine with strict transition guards:

```text
(absent) ──reserve──► RESERVED ──allocate──► ACTIVE ──settle(consumed>0)──► CONSUMED
                         │                      │
                         ├──expire──────────────┴──► EXPIRED
                         ├──compensate────────────────────────► COMPENSATED
                         └──settle(consumed>0)────────────────► CONSUMED
EXPIRED ──compensate──► COMPENSATED
```

- **Outstanding States**: `RESERVED`, `ACTIVE`
- **Terminal States**: `CONSUMED`, `EXPIRED`, `COMPENSATED`
- **Compensation Rules**: `COMPENSATED` is legal *only* from `RESERVED` or `EXPIRED`. Attempting to compensate an already terminal lease is an idempotent no-op.
- **Legacy Aliases**: Automatically normalized on read (`ISSUED` $\rightarrow$ `RESERVED`, `CLOSED` $\rightarrow$ `CONSUMED`, `SETTLEMENT_PENDING` $\rightarrow$ `ACTIVE`, `REQUESTED` $\rightarrow$ `RESERVED`).

---

### 1.12 Schema Versioning & Upcasting Pipeline (`src/core/contracts/command_envelope.py`)

Every `CommandEnvelope` carries a `schema_version: int` (default `1`).
- Deserialization via `CommandEnvelope.from_dict(raw)` invokes `GLOBAL_UPCASTER_REGISTRY`.
- Registry keys are `(event_type, from_version)`. Commands have no `event_type`, so `from_dict` sets `event_type = command_type` before upcast.
- Upcasters execute sequentially to transform payloads from schema version $v_i \rightarrow v_{i+1}$ without requiring database rewrites or historical log mutations.

---

### 1.13 In-Process Pipeline Authority Runtime (`src/core/frontier/authority_runtime.py`)

Single-node CLI and dashboard executions instantiate `PipelineAuthorityRuntime`, which hosts all authority objects within the process:
- **Partition Log**: Single-node leader Raft instance (`P-0000`, quorum 1).
- **Budget Enforcer**: `HuntBudgetEnforcer` attached to `GlobalBudgetAggregate`.
- **Policy Gate**: `PolicyGovernanceGate` attached to authoritative replicated log.
- **QoS & Flow Control**: `PrioritizedRealtimeBroker` (P0–P4 lanes) + `AdaptivePIDController` + `BayesianParameterBandit`.
- **Factory / Binding**: `attach_pipeline_authority(orchestrator, run_id, config)` lives in `src/pipeline/authority_bootstrap.py` (core stays stage-pure). It constructs HuntBudget/bandit/authorizer and calls `PipelineAuthorityRuntime.attach_to(orchestrator)`.

### 1.14 Additional FSM result codes (implemented, not exhaustive)

`PARTITION_MISMATCH`, `NEGATIVE_BUDGET_ALLOCATION`, `POLICY_GENERATION_REVOKED`, `POLICY_GENERATION_EXCEEDS_WATERMARK`, `SUBLEASE_BALANCE_EXCEEDED`, `NOT_YET_EXPIRED`, `POLICY_VERSION_FENCE_FAILED`, `NO_PARENT_POLICY`, `UNKNOWN_COMMAND_TYPE`, `NON_POSITIVE_UNITS`.

---

## 2. Recovery & Replay Invariants

1. **Replay Invariant**: Replaying from certified snapshot $S$ through committed index $K$ yields identical state hash:
   $$\text{SHA256}(\text{CanonicalEncode}(\text{FSM at } K)) == \text{Receipt.state\_hash\_at\_commit}$$
2. **Crash Resilience (Invariant I15)**: Any CRC-64 mismatch or corrupted record in `PartitionWAL` or `DurableOutboxLedger` aborts recovery fail-closed (`WALCorruptionError`) with zero state mutations.
3. **Receipt Authenticity (Invariant I13)**: Command receipts are signed via HMAC-SHA256 over canonical bind payloads containing `(command_id, partition_id, raft_term, raft_index, entry_hash, previous_state_hash, state_hash_at_commit, signer_key_id)`.
4. **Checkpoint Projection Invariance (INVARIANT-007)**: Checkpoint files are Level 3 materialized read projections and can never override or contradict the authoritative Raft FSM state. Stale or diverging checkpoints are rejected during recovery screening.
5. **Recovery Protocol (Invariant I35)**: Restart walks `src/core/frontier/recovery_protocol.py`. PartitionWAL is the L0 source and is not reconstructed. FSM, budget, policy, and outbox rebuild from committed entries (EventId dedupe). A snapshot newer than the reader is unreadable. Crash between WAL commit and outbox append rebuilds the outbox; crash between outbox and delivery replays dispatch (I32); crash during compensation replays I28 idempotently. DeliveryLedger and checkpoints are caches.
6. **Region Consistency (Invariant I36)**: Commands are admitted only on the current leader home (`propose_and_commit` + `assert_region_may_accept_command`). `WALReplicationRelay.reconcile_with_peer` drops settlement/command rows and never calls `append_settlement_intent`. Budget reserve/settle refuse a foreign `request_region` / `settle_region`. In-flight attempts do not migrate. Healing uses `placement_version`, never LWW.
