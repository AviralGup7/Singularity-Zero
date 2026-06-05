# Pipeline Orchestration: Deep Architectural Analysis (2026-Q2)

> **Implementation Status (2026-06-06):** Sections 1–6 have been implemented.
> - §1 DAG: static tiers replaced by `ActorScheduler` with per-node readiness,
>   single `Graph` DSL, eager speculative dispatch, `IfStage` conditionals,
>   critical-path priority sorting. `_check_parallel_consistency` removed.
> - §2 Circuit Breaker: wired into `ToolExecutionService` as `dict[str, CircuitBreaker]`;
>   `can_execute()` gates subprocess before retry loop; per-tool `recovery_timeout`;
>   `force_open` hot-path wired to self-healing controller with HALF_OPEN probe scheduling.
> - §3 Retry: split into `StageRetryPolicy` + `ToolRetryPolicy`; per-stage
>   `max_retry_budget_seconds`; `AdaptiveBackoffHeuristic` (Vegas-style, 1.0→4.0);
>   `sleep_before_retry_async` cancellation-safe; structured `RetryEvent` emission.
> - §4 Parallel: adaptive `compute_pool_size()` from cached heuristics;
>   `_run_layer_with_work_stealing()` via `asyncio.Queue`; `LayerResult` partial/total
>   failure distinction; real `ThreadPoolExecutor` in sync path; dynamic expansion.
> - §5 Cache: `UnifiedCache` facade (SQLite + file); `CoalescingCacheWrapper` for
>   single-flight; CRITICAL/TRANSIENT priority queue; `STALE_WHILE_REVALIDATE` mode;
>   stage partitioning.
> - §6 Self-Healing: `push_health_metric()` via EventBus; `DampeningWindow` per-action
>   cooldowns; `CorrectionHistoryStore` auto-degradation at 40% failure to
>   `ESCALATE_ANALYST`; wired to `NotificationManager` (webhook/Slack/SMTP).
>
> This document is a **concept-level audit** of `src/pipeline/`. It is intentionally
non-implementation: it covers architectural weaknesses, missing capabilities, and
strategic thinking gaps, not code-level bugs. Findings here complement the
[FAILURE_MODES.md](FAILURE_MODES.md) runtime handbook and the branded
[architecture.md](architecture.md) capability walkthrough.

> **Scope**: `src/pipeline/` (DAG engine, services, cache, retry, self-healing,
> maintenance, tools, validation, screenshots, parallel analysis) and the
> execution-mode contract between local and distributed runs.
>
> **Audience**: pipeline engineers, SRE, and security architects evaluating
> the next evolution of the orchestration layer.
>
> **Tone**: opinionated and innovative. Where the implementation is sound, the
> doc says so. Where it is rigid, the doc prescribes a direction, not a patch.

---

## 1. DAG Execution — Static Tiers Hide Modern Orchestration Gaps

### How it works today

`PipelineDAG.compute_execution_plan()` runs Kahn's algorithm against the
`STAGE_DEPS` adjacency list and produces a list of `ExecutionTier` objects. Each
tier is then executed with `asyncio.gather(*workers)`. A separate
`PARALLEL_STAGE_GROUPS` constant is applied as an *override* on top of the
topological result, with `_check_parallel_consistency()` only *warning* on
contradictions rather than refusing to run.

### What is missing

- **Speculative / eager dispatch.** Stages whose dependencies are already
  satisfied must wait until the *entire* previous tier finishes. If `nuclei`
  only depends on `urls`, and `urls` completes in 4 s while `subdomains` is
  still grinding, `nuclei` idles. A node-ready queue (each stage awaiting
  per-dependency events) would eliminate tier-bubble stalls.
- **Dynamic DAG mutation on findings.** The graph is locked at `__init__`. A
  stage that discovers 200 fresh domains via certificate transparency during
  active scanning cannot trigger a new passive scan without a manual re-run.
- **Critical-path / priority weighting.** A 900-second `nuclei` tier is
  treated the same as a 5-second `reporting` tier. There is no
  longest-path computation to surface the critical chain or to inform ETA.
- **Conditional / branch nodes.** The engine models stages as always-runnable.
  There is no `IfStage(condition=lambda ctx: ctx["live_hosts"])` primitive.
  Dead scopes pay full price.
- **DAG versioning / lineage.** Replays use the same plan; there is no
  signature that allows old checkpoints to be recognized as stale.

### Recommendation

Promote each stage to a node-actor: a coroutine awaiting dependency *signals*
(events), not tier barriers. The run loop should poll per-node readiness,
dispatching greedily rather than batching by tier. Collapse `STAGE_DEPS` and
`PARALLEL_STAGE_GROUPS` into a single declarative graph DSL to eliminate the
consistency check that today only warns and does not prevent.

---

## 2. Circuit Breaker — Clean Implementation, Zero Wire-Up

`services/circuit_breaker.py` is well-built (CLOSED → OPEN → HALF_OPEN with
cached state reads to avoid lock contention, correct semantics across the
fix chain). The problem: `ToolExecutionService._run_subprocess_async()` calls
`subprocess` directly. *Nothing* in the tool execution path consults a
breaker. Every timeout, every rate-limit, every network failure re-attempts
the subprocess. The existing `RetryPolicy` only governs the *intra-call*
retry envelope, not *cross-call* gating.

In a long run, a flaky `subfinder` (or a blacklisted crt.sh source) burns
50+ spawn cycles before the pipeline "learns" it is down. There is no
mechanism for the orchestrator to stop calling a tool it has empirically
seen to be unhealthy.

### Recommendation

`ToolExecutionService` must own a `Dict[str, CircuitBreaker]`, keyed by tool
name, with a per-tool `failure_threshold`, `recovery_timeout`, and
`expected_exception` filter (e.g., HTTP 429 should trip, "binary not found"
should not). The gate must be checked *before* `subprocess.Popen`, not after.
The self-healing controller should be able to remotely `force_open()` a tool
and schedule a half-open probe on a configurable schedule.

---

## 3. Retry — Robust Math, Wrong Granularity

### Strengths

Exponential backoff with capped uniform jitter. Classification into
`TRANSIENT / PERMANENT / UNKNOWN`. Structured `RetryMetrics` with
hit/miss/exhaustion counters per stage.

### Weaknesses

- **Global instance, not per-stage.** `RetryPolicy` is constructed once in
  `runtime.py` and shared. If the recon stage burns 8 of 10 retries on a
  flaky source, the active-scan stage inherits 2. The
  `min(attempt, max_attempts)` math has no concept of *remaining budget*.
- **No feedback loop.** The multiplier is fixed at `2.0`, jitter at `0.25`.
  If telemetry observes that 80 % of third retries also fail, the system
  does not lengthen the next backoff. A simple EMA of "success rate by
  retry depth" can drive `backoff_multiplier` from 2.0 → 4.0 adaptively.
- **Cancellation-unaware sleep.** `time.sleep(backoff)` inside an `async`
  retry loop blocks the event loop. With a 64 s backoff, `KeyboardInterrupt`
  is delayed by up to 64 s.
- **No idempotency keys.** A GET to crt.sh is idempotent; a POST to an
  external service is not. Without idempotency tags, retrying after
  partial success is unsafe.

### Recommendation

Split into `StageRetryPolicy(budget_seconds, max_attempts)` (per-stage,
separate from the per-call retry) and `ToolRetryPolicy(initial, multiplier,
jitter, max)` (per-tool call). Replace `time.sleep` with
`await asyncio.sleep` and check `shutdown_event` on wake. Emit
`retry_attempt_completed` events on the bus so the self-healer can
auto-shorten downstream stages when a tool's success rate drops.

---

## 4. Parallel Analysis — Bounded Gather, Misses the Larger Picture

`ParallelAnalysis` uses `asyncio.gather` with a semaphore and an inner
`ThreadPoolExecutor` for blocking tool calls. It conflates *concurrency*,
*parallelism*, and *optimal resource use*.

### Missing strategies

- **Work stealing.** Static pools are fine for homogeneous loads, but stages
  have wildly different per-task times. A long-running `nuclei` task
  shouldn't block 10 small `httpx` probes from starting.
- **Per-host / per-target parallelism.** Concurrency is global; if one
  target has 10,000 URLs and another has 5, the global pool starves the
  small one.
- **Backpressure to upstream producers.** If the active-scan queue is full,
  the recon stage should slow down, not enqueue and OOM.
- **Adaptive scaling.** A trivial `psutil.cpu_percent()` watcher could
  raise / lower the semaphore dynamically. Static `max_workers` ignores
  host saturation.
- **Affinitization.** I/O-bound stages want more workers; CPU-bound
  (semgrep, nuclei templating) wants fewer. A
  `Stage.parallelism_profile = "io" | "cpu" | "mixed"` would let the
  scheduler pick counts intelligently.

### Recommendation

Introduce a `ParallelismProfile` enum. Replace the global semaphore with
`host-aware` and `profile-aware` semaphores, both gated by `psutil` and a
sliding-window load average. Add a `DrainableQueue` upstream so producers
can pause when consumers are saturated.

---

## 5. Caching — SQLite Is Right, but the Strategy Is One-Dimensional

### What's there

`CacheManager` is file-backed JSON with atomic writes, gzip, and LRU
eviction via `OrderedDict.move_to_end`. `CacheBackend` is SQLite with WAL,
batched transactions, and namespacing.

### What's missing

- **Negative caching with TTLs.** A "0 results" entry is never written, so
  the same dead host is hit 100 times. A `negative_ttl` would prevent that.
- **Cache key normalization.** `http://x.com/`, `https://x.com/`,
  `www.example.com` and `Example.com` almost certainly hash differently. A
  `normalize_target()` preprocessor is mandatory.
- **Cache invalidation on tool/version change.** `nuclei v10` results in
  cache may not match `nuclei v11`. The cache key should include tool
  version + template hash.
- **Tiered cache (L1 in-memory, L2 on-disk).** Every cache hit pays
  JSON-deserialize cost. A small `functools.lru_cache` wrapping
  `CacheManager` for hot keys would cut p99 latency dramatically.
- **Cache poisoning defense.** A corrupted cache file is silently accepted.
  A blake2b of the value, signed by content, prevents tampering when the
  cache is read-only by the orchestrator.
- **Cache hierarchy across runs.** A `cache_for_run(run_id)` namespace is
  implicit; an explicit `cache_namespace` field would let teams share
  cache across pipelines (e.g., recon cache for everyone).

### Recommendation

Add a `CacheKeyNormalizer`. Embed tool version + template SHA in the cache
key. Add LRU-in-memory fronting the on-disk cache. Expose
`flush_namespace()` and `warm_cache()` APIs so CI can pre-seed.

---

## 6. Self-Healing — Polling, Not Observing

`SelfHealingController` polls a `MetricCollector` on an interval, evaluates
`corrective_actions`, and triggers them. It is a watchdog.

### Problems

- **Polling latency.** If the interval is 30 s, a stuck stage has 30 s of
  purely reactive delay. Push-based alert routing is the modern pattern.
- **Reactive, not predictive.** It responds to broken, not to *trending
  broken*. No EWMA on tool failure rate, no seasonality awareness.
- **Predefined corrective actions.** A hand-curated "if X then do Y" list.
  The controller cannot synthesize new actions from a finding.
- **No global state.** Each controller is local. In a distributed run, two
  controllers will both notice a tool is down and both trip the breaker —
  racing.
- **Shallow health checks.** "Did the stage emit `completed`?" is the
  typical signal. No internal liveness probe during a long `nuclei` run.

### Recommendation

Move from poll to push: stages emit `heartbeat`, `progress`, `metric`,
`error` events on the bus. The controller subscribes and applies rules. Add
a small in-memory time-series DB (fixed-size ring buffer per metric) for
trend detection. Add `corrective_action_effectiveness()` that scores each
action's success rate and demotes ineffective ones. In distributed mode,
the controller should be leader-elected (`Redis SET NX`) to avoid duplicate
trips.

---

## 7. Maintenance — Schedule-Wall-Clock, Not Event-Wall-Clock

`maintenance.py` is a cron-style pruner: rotate output, clean cache by age,
snapshot metrics. Correct but limited.

### Missing

- **Trigger-based maintenance.** "Rotate output *when it exceeds 1 GB*."
  "Clean cache *when hit rate drops below 30 %*." A static `every 6 hours`
  is a heuristic, not a system.
- **Cross-pipeline observability.** It operates on the *current* run's
  outputs. No central `PipelineArchive` for cross-run trend analysis
  ("scope X is 2× noisier this week").
- **No retention policy DSL.** Hard-coded `keep_last_n=5` does not compose
  with "keep all critical findings forever."
- **Snapshot rollback.** It *saves* a metric snapshot but does nothing
  with it. A `restore_metrics_to(snapshot)` API or a regression detector
  ("new run is 3× slower than snapshot N") would be useful.

### Recommendation

Convert maintenance from a scheduler into a *policy engine* with
`Rule(when=Metric(...), action=...)`. Each rule fires when the predicate is
met, not on a wall-clock tick. Add a `maintenance_audit.log` with before/
after state and a `dry_run` flag for CI.

---

## 8. Tools & Capabilities — Capability Negotiation Is Half-Done

`ToolRegistry` with `register(name, binary, capabilities)`. `tools_capabilities.py`
defines capability tags. `ToolExecutionService` resolves and runs.

### Gaps

- **No capability-based routing.** The pipeline checks "is `nuclei`
  available?" but does not say "`nuclei` *can* do CVE lookup and *cannot*
  do binary static analysis" — even though the capability map exists.
  Stages don't declare required capabilities; they assume tool presence.
- **No capability overlap detection.** If `nuclei` and `semgrep` both claim
  "vuln scanning," there is no warning that they overlap, or that one can
  substitute the other if down.
- **No version requirement.** A `capability(version>=10.0)` predicate would
  let the orchestrator refuse to dispatch a stage requiring a feature the
  installed tool lacks.
- **No pre-flight self-test.** A tool is "registered" if the binary path
  resolves, not if it actually runs (`nuclei -version` might hang).
- **Static, not introspected.** Capabilities are hand-written. A tool that
  could declare its own capabilities at registration is more robust.

### Recommendation

Add `Stage.requires = [Capability.CVE_SCAN]` and let the orchestrator pick
the best matching tool. A `capability_score(tool, capability)` function with
weights (cost, accuracy, version) would let the orchestrator *choose*
between overlapping tools. Add a `preflight` flag that runs `--version` on
every registered tool at startup and refuses to dispatch to a broken one.

---

## 9. Validation — Pre-Flight, Not Continuous

`validation.py` is one-shot: validate input URLs, scope, config. It runs at
startup. There is no validation *between* stages.

### Missing

- **Output validation.** When `subfinder` returns 10,000 subdomains, no
  sanity check ("did we get at least 1 result for a 50-host scope?"). A
  `Stage.postcondition: Schema` is needed.
- **Schema evolution.** Input schemas are implicit. JSON-Schema-defined
  `StageInput` / `StageOutput` would let the orchestrator refuse to feed a
  v1 stage with v2 output.
- **Cross-field invariants.** "If `passive_recon_enabled=False` and
  `brute_force_enabled=True`, fail." These cross-stage invariants are not
  expressible today.
- **Sampling-based validation.** With 10,000 results, validate 100
  randomly and refuse the rest if they fail. Cheap, robust.
- **Provenance.** The validation result is not persisted; on a replay
  there is no record of *which schema* was applied at the time.

### Recommendation

Add `Stage.contract = StageContract(input_schema, output_schema, invariants)`
and run `validate_output()` after every stage. Persist the contract version
alongside the stage output so replays can detect drift.

---

## 10. Visual Testing — Solid Foundation, Lacks CI-Native Semantics

`screenshots.py` uses `playwright` headless with `ThreadPoolExecutor`.
`screenshot_diff.py` uses PIL + `structural_similarity` (SSIM) and writes
diff PNGs. Good core.

### Missing

- **Baseline governance.** Where do baselines come from? A `BaselineProvider`
  is implicit; should be explicit (local dir, S3, Git LFS). No
  `approve_baseline()` workflow.
- **Threshold per-region.** SSIM is global. A `region: (x, y, w, h)` list
  with per-region thresholds ("ignore the ad banner, but flag the login
  button") is the modern pattern (Percy, Chromatic).
- **Flake detection.** A single test run with 1 flake shouldn't fail the
  build. The diff doesn't track *flakiness* — only delta. A
  `flakiness_score = stdev(diff_score over N runs)` would help.
- **Determinism.** A screenshot at T1 ≠ screenshot at T1.1 s due to fonts,
  JS, animation. No "freeze-time" semantic.
- **Accessibility and SEO overlays.** Visual diffs are pixel-level; semantic
  diffs (alt text, color contrast) need DOM-level access.
- **Storage cost.** PNGs are large. WebP/AVIF + crop-on-diff is cheaper.

### Recommendation

Add a `BaselineManager` with `pull` / `push` / `approve` and a `RegionList`
for ignoring flaky zones. Track per-test flake history; only fail on
persistent diffs. Capture deterministic snapshots with
`page.emulate_media({reduced_motion: 'reduce'})` and `prefers-reduced-motion:
reduce`. Add a `report.json` with per-region deltas for CI annotations.

---

## 11. Rigidity — The Pipeline Is Too Linear; Findings Don't Reshape It

This is the single biggest *architectural* gap. The pipeline is a fixed
sequence of stages. Findings are *outputs* — they never reshape the plan.

Examples of rigidity:

- **No dynamic re-scoping.** A finding that lists 200 new domains discovered
  via cert transparency during the active scan cannot trigger a new passive
  scan without a manual re-run.
- **No triage-driven prioritization.** A "critical CVE" finding does not
  promote the affected target to a high-priority bucket for follow-up
  stages.
- **No early-termination on hard failure.** A stage that fails
  catastrophically (`nuclei` can't even start) still waits for the full
  timeout.
- **No "explore then exploit" pattern.** The recon stage produces a list,
  the next stage acts on the entire list. There is no `reinforcement_loop`
  where a finding causes a re-query.
- **No plan introspection from the controller.** The self-healer cannot
  say "skip the next stage, it's redundant given this finding." It only
  fixes broken things.

### Recommendation

Add a `PlanRewriter` interface. Every stage returns a `StageOutcome`
containing `plan_modifications: List[PlanOp]` (`InsertStage(after=X)`,
`SkipStage(X)`, `PromotePriority(X)`, `ReScope(X, target_list)`). The
orchestrator applies these between tiers. This single change transforms
the pipeline from a static graph to an adaptive one. Pair it with a
`Rule(when=Pattern(matcher=...), then=PlanOp...)` engine so security
engineers can express "if finding contains CVE-2021-44228, inject
`log4shell_deep_scan` after the current stage" declaratively.

---

## 12. Resume — Checkpoint Schema Is Implicit, Not Versioned

`CheckpointPersistence` writes JSON snapshots to disk. On resume, it reads
the most recent and rehydrates `PipelineContext`. The challenge:

- **Implicit schema.** The JSON structure mirrors the dataclasses. Any
  rename, type change, or default change silently breaks deserialization
  on resume across versions.
- **No checksums.** A corrupted checkpoint is loaded without detection. A
  blake2b of the serialized blob, verified on read, prevents this.
- **WAL-only durability for SQLite cache, not for the checkpoint itself.**
  The checkpoint is a single `fsync` away from being torn. `tempfile +
  os.replace` is atomic only if the filesystem supports it.
- **Incomplete state capture.** Not every side effect is checkpointed
  (ephemeral files, open subprocess handles, in-flight async tasks). On
  resume, these are leaked.
- **No idempotency tokens.** A partially-completed stage whose `start`
  event was recorded but `end` was not — on resume, is it re-run or
  skipped? No clear rule.
- **No replay determinism.** Even with a perfect checkpoint, clock drift,
  network state, and tool versions make resume *not* bit-equivalent to
  the original. The diff isn't surfaced.

### Recommendation

Introduce a `CheckpointSchema(version, magic, hash, created_at)`. Refuse
to load a checkpoint with an unknown version (offer migrate, don't
auto-apply). Use `chicken-egg` ordering: write to `*.tmp`, `fsync` the
directory, `os.replace` to final name. Add a `ResumeMode` parameter:
`"skip_completed" | "rerun_from_failed" | "rerun_all"`. Capture the *plan
signature* (DAG hash) inside the checkpoint; refuse to resume a checkpoint
against a different plan.

---

## 13. Event-Driven vs Polling — A Hybrid With Polling Bias

There is an `EventBus` (synchronous, in-process) used by tools and
validation, but `self_healing.py` polls every 30 s, `maintenance.py` uses
cron-style scheduling, and `parallel_analysis.py` uses `asyncio.gather`
with no event-driven backpressure. The architecture is mostly polling.

### Recommendation

Standardize on an event-sourced execution model:

- Every state transition emits a `StageEvent` (started, progress,
  completed, failed, skipped).
- All control loops subscribe: the self-healer, the maintenance
  scheduler, the progress UI, the metrics exporter.
- Polling becomes the *fallback* when no events arrive (a stuck-stage
  detector that *also* uses heartbeat timeouts).
- Persist the event stream to a WAL so replays are possible (event
  sourcing).
- Use an outbox pattern for cross-process events (publish to a queue,
  ack after consumption).

This single change collapses a lot of code and makes the system easier to
test (a deterministic event log = a deterministic replay).

---

## 14. CI/CD Integration — The Replay Parity Check Is a Footgun

`runner_support.py` includes `replay_with_parity_check()`. In theory,
replay the same run and assert the same events. In practice:

- **Clocks drift.** Timestamps will not match.
- **Tool outputs are non-deterministic.** `nuclei` finding order, scanner
  timing, IP resolution order.
- **Network state changes.** A CDN rotates, the diff is huge, but it
  isn't a bug.

The "parity" definition should be *semantic*, not byte-equivalent: "same
stages ran, same findings found, same criticality distribution, but
timestamps and ordering of equal-priority findings may vary."

### Other CI/CD gaps

- **No native GitHub Actions / GitLab CI integration.** No JUnit XML, no
  SARIF, no GitHub Code Scanning alerts format. CI consumers must build
  their own converters.
- **No PR-comment bot integration.** Findings don't surface as a PR
  comment without custom code.
- **No incremental runs.** CI must run the full pipeline. No
  `git diff` → "only test files changed" → "only run static analysis"
  fast path.
- **No artifact publishing.** Outputs (reports, screenshots, logs) are
  not auto-published to CI artifacts.
- **No status checks / required checks.** CI doesn't know what to *gate*
  on. A `pipeline.fail_on = "critical"` policy is missing.
- **No webhooks for partial progress.** Long pipelines need to push
  progress to Slack / Teams. The event bus exists but there is no
  webhook sink.

### Recommendation

Add a `CIIntegration` layer with adapters: `JUnitReporter`,
`SARIFReporter`, `GitHubCodeScanning`, `GitLabCodeQuality`,
`PRCommenter`. Define a `PipelinePolicy(fail_on=Severity,
max_findings=N)`. Add `incremental_diff()` that compares the changed
file set to a `Stage.trigger_patterns = [Glob(...)]` map and skips
non-matching stages. Add an `artifact_publisher` that uploads reports on
completion or failure.

---

## 15. Distributed vs Local — The Gap Is Wider Than It Looks

There is a `distributed_lock` mechanism (Redis-style via `CacheManager`).
The rest of the system is squarely single-process:

- **`asyncio.gather` does not scale across machines.** A genuinely
  distributed run needs a job queue (Celery, RQ, Temporal, Ray) where
  each worker pulls a `StageTask` from a broker.
- **No worker registration / discovery.** Workers don't heartbeat to a
  coordinator. No concept of "Worker A handles `nuclei`, Worker B
  handles `httpx`."
- **No sharding of work across workers.** Even with a queue, who decides
  that `nuclei` should target host 1–50 on worker A and 51–100 on worker
  B? No work-distribution policy.
- **No shared cache semantics across workers.** Two workers in two
  processes will both miss the same cache key, both fetch, both write.
  A distributed cache (Redis) is implied but not formalized. The local
  SQLite WAL is not safe for multi-writer distributed use.
- **No state coordination.** `PipelineContext` is in-process state. A
  worker pulling a task needs the *full* context. Snapshotting the
  context into the queue message is a heavy serialization tax.
- **No leader election.** A long-running orchestrator process is a SPOF.
  Multi-coordinator HA is not addressed.

### Recommendation

Model the pipeline as a *workflow* (Temporal / Prefect / Argo Workflows)
and adapt the existing `PipelineDAG` to that engine. Short of that,
formalize:

- `WorkerRegistration`: workers register their `capabilities: Set[Tool]`,
  `max_concurrency`, `health`.
- `WorkDistributor`: a coordinator hashes the target set to workers and
  emits `StageTask(targets=...)` messages.
- `DistributedCache`: a Redis-backed adapter for `CacheBackend` with the
  same interface; SQLite becomes a local L1.
- `LeaderElection`: `CacheManager.acquire("orchestrator-leader", ttl=30)`
  and renew on heartbeat; on lease loss, the new leader takes over from
  the last persisted checkpoint.
- `SharedContext`: persist the full `PipelineContext` to the cache after
  every stage, with a version; workers fetch it on demand rather than
  receiving it in the message.

---

## Summary — The Five Highest-Leverage Changes

If the next evolution budget is constrained, these five moves concentrate
the most architectural leverage:

1. **Node-actor scheduler with dynamic plan rewriting.** Replace
   tier-batched execution with a node-ready event queue, and let stages
   emit `PlanOp` to reshape the DAG mid-run. This single change unlocks
   adaptive behavior everywhere.
2. **Wire the circuit breaker into the tool execution path.** No
   subprocess without a per-tool breaker gate. Add a per-tool
   `expected_exception` filter so rate limits trip the breaker, not just
   spawn failures.
3. **Event-sourced control plane.** All state transitions emit events;
   all control loops subscribe. Eliminates polling, enables distributed
   replay, gives free observability.
4. **Versioned, hash-protected checkpoints with explicit resume modes.**
   Schema version + blake2b + `ResumeMode` enum. Refuse to load a
   checkpoint whose DAG signature doesn't match the current plan.
5. **CI-native output and policy layer.** JUnit, SARIF, GitHub Code
   Scanning, PR comments, incremental diffs, `PipelinePolicy(fail_on=...)`.
   The pipeline is great; the *interface to CI* is the gap that prevents
   adoption.

These are not code changes — they are *concepts* that, if adopted, turn
the pipeline from a strong single-process orchestrator into a system that
competes with Temporal, Argo, and Prefect in 2026. The bones are good.
The orchestration philosophy needs to catch up.

---

## Cross-References

- [architecture.md](architecture.md) — branded, capability-focused
  walkthrough of the mesh and platform.
- [architecture-overview.md](architecture-overview.md) — non-marketing
  codebase map and standard patterns.
- [FAILURE_MODES.md](FAILURE_MODES.md) — runtime diagnostics handbook.
- [multi-region.md](multi-region.md) — cross-region topology and
  sharding models.
- [performance.md](performance.md) — SIMD / actor migration / hardware
  benchmarks.
- [dynamic-plugins.md](dynamic-plugins.md) — hot-load third-party
  security checks.
