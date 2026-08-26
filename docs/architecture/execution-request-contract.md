# ExecutionRequest: The Contract of Intent

The **`ExecutionRequest`** is the canonical, immutable contract of intent that cleanly decouples the **Decision** subsystem (which strategizes, plans, and selects attacks) from downstream **Authorization**, **Scheduling**, and **Execution Workers** (which execute actions statelessly and deterministically).

---

## 🏛️ Architectural Handoff Pipeline

```text
Decision Engine (src/decision/)
       │
       ▼  (emits immutable intent with candidate_id, lease_id, execution_id, policy_version)
ExecutionRequest
       │
       ▼  (verifies scope, policies, and reserves request budget)
Authorization Gate (src/decision/authorization.py)
       │
       ▼  (yields single-use AuthorizedExecutionTicket with nonce)
Scheduling & Mesh Capacity (src/pipeline/services/pipeline_orchestrator/)
       │
       ▼  (dispatches placement lease to worker: LEASED, DEFERRED, REJECTED)
Worker Execution (src/execution/request_executor.py)
       │
       ▼  (strictly requires AuthorizedExecutionTicket, executes statelessly in sandbox)
ExecutionResult (findings, state_deltas, resource_consumption, identities)
       │
       ▼  (sole production settlement path)
Settlement Coordinator (src/core/frontier/state_authority.py)
       │ (Mints immutable SettlementIntent)
       ▼
StateAuthority (Single Atomic WAL Append Boundary)
       │
       ├── StateProjection (CRDT LWW-Set Deterministic Merge)
       ├── BudgetProjection (HuntBudgetEnforcer commit / release)
       └── LeaseProjection (PriorityQueue ack_batch / release_batch with CandidateLease validation)
```

### Key Invariants
1. **Zero Decision Rediscovery**: Once an `ExecutionRequest` is emitted and authorized, downstream workers execute **solely against the parameters and action payloads defined in the request**. The worker requires zero callbacks or state re-evaluations against the Decision subsystem.
2. **Authoritative WAL Settlement & State Authority Isolation**: Workers never directly touch the Frontier CRDTs or Write-Ahead Log (WAL). Workers emit an `ExecutionResult` containing `state_deltas`. The Settlement Coordinator validates this result, constructs an atomic `SettlementIntent`, and commits it to the WAL via `StateAuthority`. Downstream CRDT, budget, and candidate queue state are updated via idempotent, eventually convergent projections driven by durable cursors.
3. **Execution Idempotency & Identity Binding**: Every request carries an `execution_id` (unique per dispatch attempt), `job_id`, `candidate_id`, `lease_id`, and `policy_version` to guarantee causal traceability and prevent double-commit or race conditions across worker restarts.
4. **Mandatory Ticket Execution**: The worker API strictly requires an `AuthorizedExecutionTicket`. Unauthenticated raw `ExecutionRequest` instances are rejected with `outcome="REJECTED"`.

---

## 📦 Domain Models (`src/decision/models.py`)

### 1. `TargetSpec`
Represents the target host, port, scheme, and path to be scanned or validated:
```python
@dataclass(frozen=True, slots=True)
class TargetSpec:
    host: str
    port: int = 443
    scheme: str = "https"
    path: str = "/"
    query_params: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
```

### 2. `ActionSpec`
Defines an individual probe, exploit, mutation, or fingerprint action:
```python
@dataclass(frozen=True, slots=True)
class ActionSpec:
    action_id: str
    action_type: str  # "probe", "exploit", "mutate", "fingerprint", "nuclei", "subprocess_scan"
    tool_or_detector: str
    payload: tuple[tuple[str, Any], ...] = ()
    priority: int = 100
    max_retries: int = 3
```

### 3. `CandidateLease`
Represents an active, timed lease on a prioritized candidate target:
```python
@dataclass(frozen=True, slots=True)
class CandidateLease:
    candidate_id: str
    target_url: str
    execution_id: str
    lease_id: str
    worker_id: str
    expires_at: float
```

### 4. `ResourceLimits`
Enforces hardware, concurrency, and bandwidth budgets:
```python
@dataclass(frozen=True, slots=True)
class ResourceLimits:
    timeout_seconds: float = 300.0
    max_memory_mb: int = 512
    max_concurrency: int = 4
    max_bandwidth_kbps: int = 0
    max_payload_bytes: int = 1_048_576
```

### 5. `ScopeToken`
Provides cryptographically verifiable engagement boundaries:
```python
@dataclass(frozen=True, slots=True)
class ScopeToken:
    scope_hash: str
    allowed_domains: tuple[str, ...] = ()  # Supports wildcards like "*.example.com"
    allowed_cidrs: tuple[str, ...] = ()    # Supports CIDR blocks like "10.0.0.0/8"
    forbidden_paths: tuple[str, ...] = ()  # Blacklisted endpoints like "/admin"
    issuer_signature: str = ""
    expires_at: float = 0.0
```

### 6. `ExecutionRequest`
The overarching container capturing complete execution intent:
```python
@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    request_id: str
    tenant_id: str
    target: TargetSpec
    stage: str
    actions: tuple[ActionSpec, ...] = ()
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    scope_token: ScopeToken = field(default_factory=lambda: ScopeToken(scope_hash=""))
    deadline: float = 0.0
    correlation_id: str = ""
    metadata: tuple[tuple[str, Any], ...] = ()
    execution_id: str = ""
    job_id: str = ""
    candidate_id: str = ""
    lease_id: str = ""
    policy_version: str = ""
```

### 7. `ExecutionResult`
The structured output generated by worker execution:
```python
@dataclass(frozen=True, slots=True)
class ExecutionResult:
    request_id: str
    tenant_id: str
    outcome: str  # "COMPLETED", "FAILED", "TIMED_OUT", "REJECTED", "SKIPPED"
    duration_seconds: float = 0.0
    findings: tuple[Finding, ...] = ()
    artifacts: tuple[tuple[str, Any], ...] = ()
    state_deltas: tuple[tuple[str, Any], ...] = ()
    resource_consumption: tuple[tuple[str, Any], ...] = ()
    error: str = ""
    execution_id: str = ""
    job_id: str = ""
    candidate_id: str = ""
    lease_id: str = ""
    policy_version: str = ""
```

---

## 🛡️ Scope Authorization & Gatekeeper (`src/decision/authorization.py`)

The `ExecutionAuthorizer` checks all inbound `ExecutionRequest` instances against:
1. **Wall-clock deadline**: Rejects expired requests before wasting network or compute resources.
2. **Resource sanity**: Ensures positive timeouts and valid memory ceilings.
3. **Atomic Budget Reservation**: `HuntBudgetEnforcer.reserve_with_identity()` (I30 binds `command_id` + reservation). `reserve_requests()` remains a boolean wrapper. Fenced placement (`is_fenced`) or breaker OPEN (`set_reserve_gate`) → `None`. Tickets default `partition_id="P-0000"`.
4. **Adversarial URL & Path Normalization**:
   - Strips matrix parameters (`/..;/`), unquotes percent-encodings (`/%61dmin`), collapses redundant slashes (`//admin`), and normalizes POSIX directory traversals (`posixpath.normpath`).
   - Rejects domain suffix evasion (`example.com.evil.com`) and userinfo spoofing (`example.com@evil.com`).
5. **Single-Use Nonce & Replay Resistance**:
   - Generates a signed `AuthorizedExecutionTicket` with HMAC-SHA256 signature and unique `nonce`.
   - `consume_ticket()` verifies I30 bindings, I37 live revision, then **`commit_requests(1)`** (I28). Live stages consume once in `admit_stage` (authorize → consume → sandbox) and must not consume again. Nuclei/validation/active_scan/`_tool_runner` may still `authorize()` a second ticket (double reserve — leftover).

---

## ⚙️ Candidate Lifecycle & Worker Placement

### Candidate Lifecycle
```text
AVAILABLE ──(lease_batch)──► IN-FLIGHT (CandidateLease) ──(ack_batch)──► COMPLETED
                                       │
                          (release_batch / TTL Expiry)
                                       │
                                       ▼
                                   AVAILABLE
```

### Worker Execution (`src/execution/request_executor.py`)
The `ExecutionRequestWorker` acts as a stateless, deterministic executor:
- Enforces mandatory `AuthorizedExecutionTicket` verification and nonce consumption.
- Dispatches actions to registered handlers (`probe`, `exploit`, `nuclei`, `subprocess_scan`, etc.).
- Enforces deadline timers during multi-step execution.
- Gathers findings, evidence artifacts, state deltas, and resource metrics into an immutable `ExecutionResult`.

