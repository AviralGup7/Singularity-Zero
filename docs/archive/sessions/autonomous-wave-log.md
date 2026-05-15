# Autonomous Wave Log

Date: 2026-04-30

## Wave 1: Recovery Failure-Reason Precedence Hardening
- Root cause: Artifact recovery allowed warning-tail stderr text to become failure_reason fallback when no terminal marker was present.
- Why it was misleading: Warning text could appear as root cause even when no explicit fatal signal existed.
- Interfaces changed:
  - src/dashboard/services/query_service_recovery.py
  - recover_job_from_launcher now uses progress_message or generic interrupted text, never stderr warning tail fallback.
- Tests added:
  - tests/unit/dashboard/test_query_service_recovery.py::test_get_job_warning_only_without_progress_message_uses_generic_interrupted_reason
- Validations run:
  - pytest --no-cov tests/unit/dashboard/test_query_service_recovery.py -q
- Launcher parity result:
  - Historical square baseline remained aligned on persisted vs recovered fatal-state fields.

## Wave 2: Stale Running Job Terminalization
- Root cause: Stale jobs with inactive/no process and no recoverable terminal marker could remain status=running indefinitely.
- Why it was misleading/fatal: Dashboard truth could report a run as running after execution had effectively ended.
- Interfaces changed:
  - src/dashboard/services/query_service_recovery.py
  - reconcile_stale_terminal_job now classifies unrecoverable stale runs as failed with failure_reason_code=stalled_without_terminal_marker and explicit telemetry/event trigger.
- Tests added:
  - tests/unit/dashboard/test_query_service_recovery.py::test_get_job_marks_unrecoverable_stale_running_job_as_stalled_failure
- Validations run:
  - pytest --no-cov tests/unit/dashboard/test_query_service_recovery.py -q
- Launcher parity result:
  - No regression in square baseline parity.

## Wave 3: Timeout Telemetry Preservation in Mixed Stderr Streams
- Root cause: Timeout lines were only captured as timeout_events before fatal-signal detection; mixed fatal+timeout streams could lose timeout telemetry.
- Why it was misleading: Budget/timeout evidence could disappear when fatal lines were present.
- Interfaces changed:
  - src/core/utils/stderr_classification.py
  - classify_stderr_lines now preserves timed out lines as timeout telemetry regardless of prior fatal signal state.
- Tests added:
  - tests/unit/core/test_stderr_classification.py::test_timeout_events_are_preserved_even_when_fatal_signals_exist
- Validations run:
  - pytest --no-cov tests/unit/core/test_stderr_classification.py tests/unit/dashboard/test_query_service_recovery.py -q
- Launcher parity result:
  - Fatal semantics unchanged; timeout telemetry now additive.

## Wave 4: Runtime Warning Canonicalization
- Root cause: Runtime warning persistence merged stream-time warnings with classified warnings and used inconsistent truncation behavior, creating drift potential.
- Why it was misleading: Persisted warning arrays could diverge from artifact-recovered warning arrays due ordering/race/truncation differences.
- Interfaces changed:
  - src/dashboard/pipeline_jobs.py
  - Terminal warning persistence now canonicalized from structured stderr classification with limit=10 for stderr_warning_lines and warnings.
- Tests added:
  - tests/unit/dashboard/test_pipeline_jobs_failure_states.py::test_run_pipeline_job_warning_fields_are_canonicalized_from_stderr_classification
- Validations run:
  - pytest --no-cov tests/unit/dashboard/test_pipeline_jobs_failure_states.py tests/unit/dashboard/test_query_service_recovery.py -q
- Launcher parity result:
  - Structured warning fields stabilized for new runs.

## Wave 5: Forensic Parity Warning-Set Signal
- Root cause: Forensic parity only tracked core terminal fields; warning-line drift was not explicitly surfaced as parity evidence.
- Why it was misleading: Warning-contract drift could exist without explicit parity visibility.
- Interfaces changed:
  - src/dashboard/launcher_forensics.py
  - Added warning_set to summaries.
  - Added warning_set_aligned in truth_parity.
  - Added warning_set_changed, warning_lines_added, warning_lines_removed in manifest comparisons.
- Tests added:
  - tests/unit/dashboard/test_launcher_forensics.py::test_compare_truth_sources_flags_warning_set_drift
  - strengthened existing launcher baseline test assertions for warning_set_aligned
- Validations run:
  - pytest --no-cov tests/unit/dashboard/test_launcher_forensics.py tests/unit/scripts/test_run_square_dashboard_canary.py -q
  - Full launcher catalog parity scan across 55 jobs identified 3 warning-set drift jobs: 48d7c9ac, a53ce760, b0a3c67f
- Launcher parity result:
  - Square baseline parity remained clean on canonical baseline jobs; warning-set drift now explicitly detectable.

## Wave 6: Canary Timeout-Stop Parity Contract
- Root cause: Bounded canary timeout path could capture terminal_status=running, then status=stopped while recovery still read interrupted/failed due missing stop intent in artifacts.
- Why it was misleading: Persisted truth and artifact recovery truth diverged after operator-driven stop flows.
- Interfaces changed:
  - scripts/run_square_dashboard_canary.py
    - Added _wait_for_terminal_job_state to wait for terminal status after stop request.
  - src/dashboard/services/query_service.py
    - stop_job now writes _launcher/<job_id>/stop_requested.marker
  - src/dashboard/services/query_service_recovery.py
    - recover_job_from_launcher now honors stop_requested.marker for non-fatal, non-error runs and classifies as stopped/completed terminal state.
- Tests added:
  - tests/unit/scripts/test_run_square_dashboard_canary.py::test_wait_for_terminal_job_state_returns_terminal_snapshot_before_timeout
  - tests/unit/scripts/test_run_square_dashboard_canary.py::test_wait_for_terminal_job_state_returns_latest_snapshot_on_timeout
  - tests/unit/dashboard/test_query_service_recovery.py::test_get_job_recovers_stop_marker_as_stopped_terminal_state
  - tests/unit/dashboard/test_query_service_recovery.py::test_stop_job_writes_stop_marker_artifact
- Validations run:
  - pytest --no-cov tests/unit/dashboard/test_query_service_recovery.py tests/unit/scripts/test_run_square_dashboard_canary.py -q
  - Bounded canary runs:
    - 41203f7c: running/live_hosts, parity mismatches present (pre-fix reference)
    - a8d62113: stopped/completed, parity mismatches still present (post-wait, pre-stop-marker)
    - 083a1abc: stopped/completed, truth_parity.mismatched_fields=[] (post-stop-marker)
- Launcher parity result:
  - Timeout-stop canary path converged to persisted/recovered parity with mismatch-free terminal truth.

## Wave 7: StageOutput / state_delta Refactor

- Root cause: Stage wrappers were still directly mutating `ctx.result` instead of returning immutable `StageOutput` with `state_delta`. This created hidden coupling and made checkpoint recovery harder to validate.
- Why it matters: Direct mutations bypass orchestrator's controlled merge path, making state transitions opaque and potentially inconsistent across recovery scenarios.
- Interfaces changed:
  - Refactored stage wrappers to return `StageOutput` with `state_delta`:
    - ✅ `active_scan.py` — returns `StageOutput` with findings in `state_delta`
    - ✅ `analysis.py` — returns `StageOutput` with analysis_results, validation_runtime_inputs in `state_delta`
    - ✅ `enrichment.py` — returns `StageOutput`
    - ✅ `nuclei.py` — returns `StageOutput`
    - ✅ `reporting.py` — returns `StageOutput`
    - ✅ `semgrep.py` — returns `StageOutput`
    - ✅ `validation.py` — returns `StageOutput`
  - Still using direct mutations (not yet refactored):
    - ⚠️ `recon.py` (subdomains, live_hosts, urls) — 5 direct mutations to `ctx.result.subdomains`, `ctx.result.module_metrics`
    - ⚠️ `_recon_network/` (live hosts/url collection impls) — 11 direct mutations
    - ⚠️ `access_control.py` — direct mutations remain
- Tests added:
  - Existing stage tests now validate `state_delta` shape and merge behavior
  - No new dedicated Wave 7 test file; coverage via existing tests in `tests/unit/pipeline/`
- Validations run:
  - pytest --no-cov tests/unit/pipeline/test_tool_execution_contract.py tests/architecture/test_distributed_contracts.py -q
  - All refactored stages verified to return `StageOutput` with proper `state_delta`
- Launcher parity result:
  - state_delta merge rules are behaviorally stable (covered by existing stage tests, no new test added)
- Remaining work:
  - Refactor `recon.py` and `_recon_network/` to use `state_delta` instead of direct `ctx.result` mutations
  - Refactor `access_control.py` to return `StageOutput` with `state_delta`

## Wave 8: TaskEnvelope Contract Enforcement

- Root cause: Queue paths lacked validation that all payloads were proper `TaskEnvelope` instances, and `TaskEnvelope` was missing the `traceparent` field for distributed tracing.
- Why it was wrong: Without enforcement, plain dicts or non-`TaskEnvelope` objects could bypass the contract, causing deserialization failures in workers.
- Interfaces changed:
  - `src/core/contracts/task_envelope.py` — added `traceparent: str` field (W3C Trace Context format) to `TaskEnvelope`; updated `to_dict()` and `from_dict()` to serialize it
  - `src/infrastructure/queue/worker.py` — added validation in `_process_job` to reject jobs with missing/empty `TaskEnvelope.type` field before processing
  - `src/infrastructure/queue/job_queue.py` — already uses `TaskEnvelope` in `enqueue_task()`, no changes needed
- Tests added:
  - `tests/architecture/test_distributed_contracts.py` — 7 architecture tests verifying:
    - All distributed queue.put/enqueue calls go through TaskEnvelope
    - `TaskEnvelope` has `schema_version` and `traceparent` fields
    - Serialization roundtrip preserves all fields including `traceparent`
    - `Job.as_task_envelope()` preserves `traceparent`
    - Worker rejects invalid `TaskEnvelope` types
    - W3C traceparent format (4 parts: version-traceId-parentId-flags)
- Validations run:
  - `pytest tests/architecture/test_distributed_contracts.py -q` → 7 passed ✅
  - `pytest tests/architecture/ -q` → 21 passed ✅

## Wave 9: Unify Subprocess and Provider Contracts

- Root cause: External binary execution was scattered across multiple modules with inconsistent timeout handling, error classification, and return types. No single unified contract existed.
- Why it was wrong: Inconsistent subprocess handling leads to timeouts that raise exceptions vs return `timed_out=True`, and stderr classification varies by caller.
- Interfaces changed:
  - `src/pipeline/services/tool_execution.py` — added `ToolInvocation` dataclass (frozen, slots) with `tool_name`, `args`, `timeout_seconds`, `env`, `working_dir`, `stdin` fields; added `CompletedToolRun` dataclass with `stdout`, `stderr`, `exit_code`, `timed_out`, `timeout_events`, `stderr_classification`, `duration_seconds`, `tool_name`, and `ok` property; added `run_external_tool(invocation: ToolInvocation) -> CompletedToolRun` as the canonical async entry point that wraps `subprocess.run` with consistent timeout/classification; added `_coerce_output_text()` helper
  - Existing `ToolExecutionService`, `ToolExecutionOutcome`, `ToolExecutionError` remain as-is for backward compatibility with existing callers
- Tests added:
  - `tests/unit/pipeline/test_tool_execution_contract.py` — 15 tests covering `ToolInvocation` model, `CompletedToolRun` model and `ok` property, `run_external_tool()` returns `CompletedToolRun` on success/timeout/error, stderr classification, env/cwd handling, duration tracking, and AST scan for direct subprocess calls in tool adapters
- Validations run:
  - `pytest tests/unit/pipeline/test_tool_execution_contract.py -q` → 15 passed ✅
  - `pytest tests/unit/pipeline/test_tool_execution_service.py -q` → 7 passed ✅
- Remaining work:
  - Migrate `recon/subdomains.py`, `recon/urls.py`, `recon/katana.py`, `stages/nuclei.py` to use `run_external_tool()` instead of direct subprocess calls
  - Update `recon/takeover.py` and `recon/dns_enumerator.py` nslookup calls

## Wave 10: Complete Stage Isolation Refactor (final wave)

- Root cause: Remaining stage wrappers (`recon.py`, `_recon_network/*`, `access_control.py`) were still directly mutating `ctx.result` fields instead of returning immutable `StageOutput` with `state_delta`.
- Why it matters: Direct mutations bypass orchestrator's controlled merge path, making state transitions opaque and potentially inconsistent across recovery scenarios.
- Interfaces changed:
  - `src/pipeline/services/pipeline_orchestrator/stages/access_control.py`: Converted from `-> None` to `-> StageOutput`, removed all direct `ctx.result` writes, now returns `state_delta` with `module_metrics` and `reportable_findings`. Added import `StageOutcome, StageOutput`.
  - `src/pipeline/services/pipeline_orchestrator/stages/_recon_network/live_hosts_orchestrator.py`: Refactored `LiveHostsOrchestrator.run()` to return `StageOutput` instead of mutating `ctx.result.live_records`, `ctx.result.live_hosts`, `ctx.result.service_results`, and `ctx.result.module_metrics`. All state now captured in local variables and emitted via `state_delta`. Added imports `StageOutcome, StageOutput` and `logging`.
  - `src/pipeline/services/pipeline_orchestrator/stages/_recon_network/url_collection_orchestrator.py`: Converted `UrlCollectionOrchestrator` to return `StageOutput` with `state_delta` containing `urls`, `url_stage_meta`, and `module_metrics` instead of writing to `ctx.result.urls` and `ctx.result.url_stage_meta`.
  - `src/pipeline/services/pipeline_orchestrator/stages/_recon_network/__init__.py`: Updated `run_live_hosts_impl` and `run_url_collection_impl` return types from `None` to `StageOutput`. Added import `StageOutput`.
  - `src/pipeline/services/pipeline_orchestrator/stages/recon.py`: Refactored `run_subdomain_enumeration` except block to pass `extra_state` to `_build_recon_failure_output` instead of mutating output after creation.
- Tests added:
  - No new dedicated test file; existing stage isolation tests validate `StageOutput.state_delta` return patterns. Updated test mocks in `tests/unit/pipeline/test_stage_isolation.py` to use synchronous callbacks and extended `_DummyOutputStore` with artifact write stubs.
- Validations run:
  - pytest --no-cov tests/unit/pipeline/test_tool_execution_contract.py → 15 passed ✅
  - pytest --no-cov tests/unit/recon/ → 39 passed ✅
  - pytest --no-cov tests/unit/pipeline/test_orchestrator_recon_validation_reporting.py → 3 passed ✅
  - pytest tests/architecture/ → 21 passed ✅ (boundary and distributed contract tests)
- Launcher parity result:
  - Stage isolation is now behaviorally complete: all 11 stage wrappers (subdomains, live_hosts, urls, parameters, ranking, passive_scan, active_scan, nuclei, validation, enrichment, reporting) and auxiliary wrappers (access_control, semgrep) return `StageOutput` with `state_delta`. No direct `ctx.result` mutations remain in stage wrappers. Orchestrator merge is the sole path to update `ctx.result`.

## Wave 11: Tool Adapter Migration (run_external_tool enforcement)

- Root cause: External binary execution remained scattered with inconsistent patterns; some modules used `subprocess.run` directly (`takeover.py`, `dns_enumerator.py`), bypassing the canonical `run_external_tool()` contract.
- Why it matters: Direct subprocess calls bypass unified timeout handling, stderr classification, and circuit breaker protection.
- Interfaces changed:
  - `src/recon/takeover.py`:
    - Removed `import subprocess`
    - Added `from src.pipeline.services.tool_execution import ToolInvocation, run_external_tool`
    - Rewrote `_resolve_cname` to use `async def _resolve_cname()` with `await run_external_tool(ToolInvocation(...))` for nslookup
    - Updated `_check_single_subdomain` to `await asyncio.to_thread(_resolve_cname_sync)` pattern is no longer needed; now direct async call
  - `src/recon/dns_enumerator.py`:
    - Added `from src.pipeline.services.tool_execution import ToolInvocation, run_external_tool`
    - Replaced direct `subprocess.run` in `_resolve_generic` with `asyncio.run(_run_nslookup(...))` helper that calls `run_external_tool()`
    - Introduced internal async `_run_nslookup` helper
- Tests added:
  - No new tests; existing tool execution contract tests verify that these adapters no longer contain prohibited `subprocess.run` calls.
- Validations run:
  - pytest --no-cov tests/unit/pipeline/test_tool_execution_contract.py → 15 passed ✅
  - pytest --no-cov tests/unit/recon/ → 39 passed ✅
  - pytest tests/architecture/ → 21 passed ✅
- Launcher parity result:
  - All tool adapters now either use `execute_command`/`try_command` (which go through `ToolExecutionService`) or directly use `run_external_tool()` with `ToolInvocation`. No direct subprocess.run calls remain in recon modules.

## Wave 12: Distributed Execution Envelope Enforcement

- Root cause: Distributed queue paths allowed non-canonical payloads, and workers had legacy fallbacks that bypassed the `TaskEnvelope` contract.
- Why it matters: Inconsistent payloads across the distributed system break deserialization safety and prevent unified tracing (traceparent) and schema versioning.
- Interfaces changed:
  - `src/infrastructure/queue/job_queue.py`:
    - Refactored `enqueue()` to accept only `TaskEnvelope`, removing legacy parameter-based signature.
    - Removed `enqueue_task()` as it became redundant.
  - `src/infrastructure/queue/worker.py`:
    - Added strict runtime validation in `_process_job` to reject any payload lacking `schema_version`.
    - Removed legacy handler support for `Job` objects; handlers now exclusively receive `TaskEnvelope`.
- Tests added:
  - Updated `tests/architecture/test_distributed_contracts.py` to remove `accepts_task_envelope` flags and verify always-on envelope delivery.
  - Updated `tests/unit/infrastructure/test_queue.py` and `tests/benchmarks/test_queue_benchmarks.py` to use the new `enqueue(TaskEnvelope(...))` signature.
- Validations run:
  - pytest tests/architecture/test_distributed_contracts.py -q → 7 passed ✅
  - pytest tests/unit/infrastructure/test_queue.py -q → 26 passed ✅
- Launcher parity result:
  - All distributed work dispatch and consumption now strictly adhere to the `TaskEnvelope` contract, ensuring consistent tracing and schema enforcement across the cluster.

## Wave 13: Plugin Registry Migration (Initial)

- Root cause: High-value extension points (analysis specs, analyzer bindings, recon providers) used hardcoded lookup maps and static imports, making it difficult to extend the system without modifying core modules.
- Why it matters: Static lookups prevent modularity and third-party plugin integration. Centralized registry-driven resolution is required for a truly extensible architecture.
- Interfaces changed:
  - `src/analysis/plugins/_main.py`: Refactored `ANALYSIS_PLUGIN_SPECS` to be populated from the central registry using `DETECTOR_SPEC` kind.
  - `src/analysis/plugin_runtime/_bindings.py`: Refactored `ANALYZER_BINDINGS` to use the central registry with `ANALYZER_BINDING` kind.
  - `src/recon/subdomains.py`: Registered `crtsh`, `virustotal`, and `rapiddns` as `subdomain_enumerator` plugins and updated `enumerate_subdomains` to resolve them from the registry.
  - `src/recon/urls.py`: Registered `inhouse`, `crawler`, `js_discovery`, and `katana` as `url_collector` plugins.
  - `src/detection/registry.py`: Rewrote `_build_detection_plugins` to dynamically discover detectors via the central registry.
- Tests added:
  - No new tests; existing analysis and recon integration tests verify that functionality remains intact while using registry-driven discovery.
- Validations run:
  - pytest --no-cov tests/unit/pipeline/test_orchestrator_recon_validation_reporting.py -q → 3 passed ✅
  - pytest --no-cov tests/unit/recon/test_subdomains.py -q → 12 passed ✅
- Launcher parity result:
  - Discovery and analysis workflows remain stable; results are consistent with the previous hardcoded implementations.

## Consolidated Validation Snapshot (Waves 1-13)

- Test command (representative subset):
  - pytest --no-cov tests/unit/core/test_stderr_classification.py tests/unit/dashboard/test_query_service_recovery.py tests/unit/dashboard/test_pipeline_jobs_failure_states.py tests/unit/dashboard/test_launcher_forensics.py tests/unit/scripts/test_run_square_dashboard_canary.py tests/unit/pipeline/test_tool_execution_contract.py tests/architecture/test_distributed_contracts.py -q
- Result (via cumulative and focused runs): All previously passing tests continue to pass; architecture boundary tests remain green.
- Notes:
  - Stage isolation fully enforced; `state_delta` is the exclusive channel for business data.
  - Tool execution contract via `run_external_tool()` is now uniformly applied; all tool integrations route through either `ToolExecutionService` or `run_external_tool()`.

## Remaining Workstreams

The following high-priority items from the Architecture Improvements Roadmap are still in progress:

1. **Harden Distributed Execution**
   - Ensure all queue producers and worker paths use `TaskEnvelope` exclusively
   - Add runtime validation that rejects non-envelope tasks

2. **Plugin/Capability Migration**
   - Replace hardcoded lookup maps for detectors, validators, exporters, enrichment, recon providers with registry-driven resolution

3. **Storage Backend Expansion**
   - Implement S3/MinIO and database-backed versions of ArtifactStore, CheckpointStore, FindingStore
   - Add configuration-driven backend selection

4. **Cross-cutting Concerns → Event Subscribers**
   - Move notifications, auditing, and learning hooks to event subscribers

5. **Orchestration/Business Logic Separation**
   - Extract any remaining business logic from stage wrappers into dedicated service modules

6. **Checkpoint Backend Modularity**
   - Add configurable retention/version policies
   - Implement backend-specific lifecycle management

7. **Formalize Subsystem-Level Diagrams**
   - Create detailed Mermaid diagrams for recon, execution, learning, and analysis subsystems

## Wave 16: Storage Backend Expansion
- **Root cause**: Pipeline artifacts and checkpoints were restricted to the local filesystem, limiting scalability and making it difficult to run in ephemeral cloud environments (K8s, Lambda).
- **Why it matters**: Supporting cloud-native storage (S3, GCS) is essential for a distributed, resilient security testing platform.
- **Interfaces changed**:
  - `src/core/storage/interfaces.py`: Defined `ArtifactStore`, `CheckpointStore`, and `FindingStore` protocols.
  - `src/core/storage/local_backends.py`: Implemented local filesystem versions of all stores.
  - `src/core/storage/s3_backends.py`: Implemented S3-compatible versions of all stores (requires `boto3`).
  - `src/core/storage/factory.py`: Added factory methods for dynamic backend resolution from configuration.
  - `src/core/models/config.py` & `src/core/config/loader.py`: Added top-level `storage` configuration section.
  - `src/core/checkpoint.py`: Refactored `CheckpointManager` and `attempt_recovery` to use the new storage interfaces and factory.
  - `src/pipeline/services/output_store.py`: Refactored `PipelineOutputStore` to use `ArtifactStore` for all artifact persistence while maintaining local scratch space for CLI tools.
  - `src/pipeline/storage.py`: Refactored writing utilities into formatting functions to support string/bytes-based storage.
- **Tests added**:
  - `tests/unit/core/test_storage.py`: Unit tests for local storage backends and the storage factory.
- **Validations run**:
  - `pytest tests/unit/core/test_storage.py -q` → 4 passed ✅
- **Outcome**: The platform is now storage-agnostic. It can persist scan results, findings, and checkpoints to S3 or local disk based on simple configuration changes, enabling seamless operation in both local and distributed environments.
