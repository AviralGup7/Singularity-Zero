# TODO — Cyber Security Test Pipeline (DAG / resilience / orchestration) Remediation

## Completed (evidence-gathering)
- Read DAG orchestration components:
  - `src/pipeline/services/pipeline_orchestrator/graph_builder.py`
  - `src/pipeline/services/pipeline_orchestrator/actor_scheduler.py`
- Read orchestration entrypoints:
  - `src/pipeline/runtime.py`
  - `src/pipeline/services/pipeline_orchestrator/_run_execution.py`
  - `src/pipeline/services/pipeline_orchestrator/orchestrator.py`
  - `src/pipeline/services/pipeline_orchestrator/_orchestrator/security.py`
- Read retry/backoff layer:
  - `src/pipeline/services/pipeline_orchestrator/_orchestrator/retry.py`
- Read tool execution + circuit breaker implementation:
  - `src/pipeline/services/tool_execution.py`
  - `src/pipeline/services/circuit_breaker.py`
- Read checkpointing:
  - `src/core/checkpoint/base.py`
  - `src/core/checkpoint/strategies.py`
  - `src/core/checkpoint/recovery.py`
- Read WAL implementation + integrity:
  - `src/core/frontier/wal.py`
  - `src/core/frontier/state.py`
- Read WAL+merge enforcement:
  - `src/pipeline/services/pipeline_orchestrator/_orchestrator/utils.py` (merge_stage_output w/ WAL durability)

## Findings (evidence-based)
- WAL write-ahead durability + CRC integrity + recovery primitives exist:
  - WAL deltas are written via `merge_stage_output(... wal=...)`
  - CRC64 corruption detection exists in `FrontierWAL`
  - `FrontierWAL.recover_state()` and `recover_deltas()` exist
- However, runtime resume/from-checkpoint/WAL-replay CLI surface and the “end-to-end replay protocol” still needs confirmation and likely wiring:
  - `run_secured()` initializes WAL but we haven’t proven it calls `recover_state()` during resume-from-checkpoint flow.

## P0 — Implement first (WAL replay/resume-from + global deadline + Retry-After aware backoff)

### P0.1 WAL-aware resume / verify / dry-run
**Target files (likely):**
- `src/pipeline/runtime.py` (CLI args)
- `src/pipeline/services/pipeline_orchestrator/_orchestrator/security.py` (`run_secured()` resume logic)
- (optional) `src/pipeline/services/pipeline_orchestrator/_orchestrator/utils.py` (diff/merge helpers)

**Steps**
1. Add CLI flags:
   - `--resume-from <checkpoint_run_id>`
   - `--wal-replay` (modes: `verify|replay|dry-run`)
2. In `run_secured()`, after initializing `orchestrator._wal`, wire:
   - `orchestrator._wal.recover_state()` when resuming
3. Verify-mode:
   - compare recovered WAL-derived frontier state vs checkpoint/neural-state summary (e.g., counts, `last_wal_id`)
4. Dry-run mode:
   - recover WAL state and compute expected stage set but do not execute tools

**Status:** Not started

### P0.2 Global max-duration deadline budgeting
**Target file:**
- `src/pipeline/services/pipeline_orchestrator/actor_scheduler.py`

**Steps**
1. Add runtime/config support for:
   - `--max-duration-seconds` (and `config.max_duration_seconds`)
2. In `ActorScheduler.run()` enforce wall-clock deadline:
   - stop dispatch
   - mark pending stages as `SKIPPED(reason="global_deadline_exceeded")`
3. Ensure exit code mapping:
   - prefer exit `4` (partial) unless policy says otherwise

**Status:** Not started

### P0.3 Retry-After aware backoff override
**Target files (likely):**
- `src/core/utils/stderr_classification.py` (or equivalent)
- `src/pipeline/retry/*` (policy sleep override hook)
- `src/pipeline/services/pipeline_orchestrator/_orchestrator/retry.py` (to pass override)

**Steps**
1. Extract `Retry-After` seconds from tool stderr/stdout when present
2. Modify retry backoff decision:
   - if Retry-After extracted, override computed backoff delay
3. Update unit tests for rate-limit responses

**Status:** Not started

## P1 — Circuit breaker persistence + proactive probe dispatch + stage isolation

### P1.1 Persist circuit breaker state
**Target files (likely):**
- `src/pipeline/services/tool_execution.py`
- new persistence in `src/pipeline/unified_cache.py` or SQLite layer

**Status:** Not started

### P1.2 Wire HALF_OPEN recovery probes into scheduler idle loop
**Target file:**
- `src/pipeline/services/pipeline_orchestrator/actor_scheduler.py`

**Status:** Not started

### P1.3 Stage data isolation (immutable stage view + delta-only writes)
**Target files (likely):**
- `src/pipeline/services/pipeline_orchestrator/_orchestrator/retry.py`
- `src/pipeline/services/pipeline_orchestrator/_orchestrator/utils.py`
- `src/core/models/stage_result.py`

**Status:** Not started

## P2 — parallel_analysis throughput/memory improvements
**Target files:**
- `src/pipeline/parallel_analysis/*`

**Status:** Not started
