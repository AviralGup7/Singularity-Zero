# Formal Command & State Transition Specification

This document defines the **Formal Command & State Transition Contract** for all operations in the Cyber Security Test Pipeline, adhering strictly to [TARGET_ARCHITECTURE.md](file:///d:/cyber%20security%20test%20pipeline%20-%20Copy/docs/TARGET_ARCHITECTURE.md).

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
  - `subleases[sublease_id] = GlobalSubLease(status="ISSUED", units=units)`
  - $\text{version}' = \text{version} + 1$
- **Emitted Domain Event**: `GlobalSubLeaseReservedEvent(run_id, partition_id, sublease_id, units)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="SUBLEASE_ISSUED")`
- **Failure Modes**:
  - `INSUFFICIENT_GLOBAL_BUDGET`: `available < units` $\rightarrow$ `REJECTED`, $\Delta \text{version} = 0$.
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
  - `aggregates[exec-9941] = AggregateState(status="RUNNING", units_reserved=5, version=1)`
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
  - `subleases[sublease_id].status = "SETTLEMENT_PENDING"`
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
  2. `sublease.status in ("ISSUED", "ACTIVE", "SETTLEMENT_PENDING")`
- **Deterministic State Transition**:
  - $\text{consumed}' = \text{consumed} + \text{units\_consumed}$
  - $\text{available}' = \text{available} + \text{units\_returned}$
  - `subleases[sublease_id].status = "CLOSED"`
  - $\text{version}' = \text{version} + 1$
- **Universal Invariant Verification**:
  $$\Delta \text{TotalBudget} = \Delta \text{Consumed} + \Delta \text{OutstandingReserved} + \Delta \text{Available} = 3 - 5 + 2 = 0$$
- **Emitted Domain Event**: `SubLeaseReconciledEvent(sublease_id, units_consumed, units_returned)`
- **Idempotency Record**: `CommandResult(status="SUCCESS", result_code="SUBLEASE_CLOSED")`

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
  2. `observed_at >= expires_at + max_skew`
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
  - `aggregates["policy_active"].status = "ROLLED_BACK"`
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
  1. `sublease_id in subleases` and `sublease.status in ("ISSUED", "ACTIVE")`.
- **Deterministic State Transition**:
  - `units_returned = sublease.units_allocated - units_consumed`
  - $\text{consumed}' = \text{consumed} + \text{units\_consumed}$
  - $\text{available}' = \text{available} + \text{units\_returned}$
  - `subleases[sublease_id].status = "EXPIRED"`
  - $\text{version}' = \text{version} + 1$
- **Universal Invariant Verification (INVARIANT-001 & INVARIANT-005)**:
  $$\Delta \text{TotalBudget} \equiv \Delta \text{Consumed} + \Delta \text{OutstandingReserved} + \Delta \text{Available} = 0$$

---

## 2. Recovery & Replay Invariants

1. **Replay Invariant**: Replaying from certified snapshot $S$ through committed index $K$ yields identical state hash:
   $$\text{SHA256}(\text{CanonicalEncode}(\text{FSM at } K)) == \text{Receipt.state\_hash\_at\_commit}$$
2. **Crash Resilience**: Any node crash during phase 1–3 of Raft replication causes zero state mutations; upon recovery, uncommitted proposals are truncated and committed entries are replayed from the replicated log.
3. **Checkpoint Projection Invariance (INVARIANT-007)**: Checkpoint files are Level 3 materialized read projections and can never override or contradict the authoritative Raft FSM state. Stale or diverging checkpoints are rejected during recovery screening.
