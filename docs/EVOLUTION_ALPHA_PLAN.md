# Singularity-Zero: Evolution Alpha - Development Roadmap

This plan outlines the major phases of development for the Cyber Security Test Pipeline, showcasing the transition from architectural foundations to a fully operational, production-grade autonomous security engine. Phases 1–4 are completed; Phases 5–11 are the active evolution roadmap.

---

## 🏗️ Phase 1: Production-Grade Mesh Orchestration
**Goal**: Move from simulated load balancing to real-time, resource-aware actor migration.

1.  **Metric-Aware Balancing**:
    *   **Status**: **COMPLETED**. Refactored `src/infrastructure/mesh/balancer.py` to ingest real-time `psutil` data.
    *   Implemented the **Suitability Score** based on CPU usage and RAM headroom.
2.  **Proactive Actor Migration**:
    *   **Status**: **COMPLETED**. Updated `src/core/frontier/ghost_actor.py` with a `MigrationTrigger` and `health_check` handler.
    *   Actors automatically signal `evacuation_recommended` when node pressure is detected, initiating dynamic state transfer and re-hydration on worker instances.

---

## 🧠 Phase 2: Autonomous Exploitation Engine (AEVE)
**Goal**: Transform finding "candidates" into verified security proof-of-concepts.

1.  **Safe-Harbor Validation**:
    *   **Status**: **COMPLETED**. Implemented `src/execution/exploiters/aeve.py` to manage the verification lifecycle.
    *   Heuristic-based validation and target containment verification are fully active.
2.  **Multi-Stage Chaining**:
    *   **Status**: **COMPLETED**. AEVE supports multi-stage attack-chain linking between exposures, active probes, and downstream vulnerability sinks.

---

## 📊 Phase 3: Visual Intelligence & Observability
**Goal**: Provide high-fidelity insights into the autonomous decision-making process.

1.  **Attack-Chain Visualization**:
    *   **Status**: **COMPLETED**. Integrated 3D instanced breakdown views and visual state-graph models of CSI vectors within the user interface (`RiskScorePage.tsx`).
2.  **Telemetry Micro-Batching**:
    *   **Status**: **COMPLETED**. Implemented micro-batched event streams to reduce frame-rate lag and stabilize high-throughput telemetry updates.

---

## 🛡️ Phase 4: Long-Term Mesh Stability
**Goal**: Resolve architectural debt and prevent state-engine degradation.

1.  **State Compaction & Pruning**:
    *   **Status**: **COMPLETED**. Implemented `VectorClock.prune` and `LWWset.compact` in `src/core/frontier/state.py`.
    *   Compaction and tombstone pruning are automatically triggered post-stage inside `_run_execution.py`.
2.  **AES-GCM Key Rotation & Disk Flushing**:
    *   **Status**: **COMPLETED**. Volatile key rotation (4-hour intervals) and memory wipes are fully operational in `GhostVFS`.
    *   Implemented secure `flush_to_disk()` inside `src/core/frontier/ghost_vfs.py` with path traversal check mechanisms to prevent directory escape.

---

## 🔄 Phase 5: Continuous Self-Learning & Autonomous Threshold Tuning
**Goal**: Close the feedback loop end-to-end. The learning subsystem (`src/learning/`) records telemetry and adjusts thresholds *between* runs, but no mechanism currently triggers automatic config mutation *during* a live scan or validates that learned thresholds constitute an improvement before the next run begins.

1.  **Adaptive Nuclei Tag Bootstrapping**
    *   **Status**: 🟢 **COMPLETE.** `src/learning/nuclei_tag_optimizer.py` implements `NucleiTagOptimizer` with per-tag TP/FP/F1 scoring, boost/demote logic, and a full unit-test suite (`tests/unit/learning/test_nuclei_tag_optimizer.py`, 369 lines, 13+ tests). `src/learning/integration.py` wires it into `compute_adaptations()` (line 207–219), and the orchestrator calls `build_nuclei_plan()` in `src/pipeline/services/pipeline_orchestrator/stages/nuclei.py` (line 83) with the live adaptive-tag override. Acceptance: ✅ adaptive tags are recomputed every run and passed through to the nuclei scanner.

2.  **Pre-Scan Config Mutation with Rollback**
    *   **Status**: 🟢 **COMPLETE.** `LearningIntegration.compute_adaptations()` / `apply_adaptations()` / `_persist_adaptive_config()` in `src/learning/integration.py` implement the full end-to-end loop: per-run adaptations are computed from telemetry, applied to the live `ctx` dict, and flushed to `<output>/config.adaptive.json` plus `<output>/config.adaptive.ledger.json` via `PipelineOutputStore.write_adaptive_config()` (`src/pipeline/services/output_store.py:150–167`). On the next run, `src/pipeline/runner_support.py:16–31` loads and merges `config.adaptive.json` before the orchestrator starts. A two-generation ledger is maintained via `config.adaptive.ledger.json`. `ThresholdTuner.is_converged` is used inside `_persist_adaptive_config` to gate promotions. Acceptance: ✅ consecutive-run threshold improvements are persisted and re-loaded automatically.

3.  **Dashboard Learning Tab**
    *   **Status**: 🟢 **COMPLETE.** `src/dashboard/fastapi/routers/learning.py` exposes `GET /api/learning/kpis` (`TelemetryKpis` schema — precision, recall, fp_rate, scan_duration), `GET /api/learning/feedback` (paginated `FeedbackEventEntry` list), `GET /api/learning/fp-patterns` (learned FP suppression patterns), `GET /api/learning/thresholds` (threshold calibration history), and `GET /api/learning/db-stats` (telemetry DB size). All four endpoints are exercised by `tests/unit/dashboard/test_learning_routes.py`. Acceptance: ✅ navigating to `/learning` on a warmed-up cluster renders real telemetry charts.

---

## 🔐 Phase 6: Automated Compliance & Regulatory Reporting
**Goal**: The compliance mapping module (`src/reporting/compliance_mapping.py`) already covers OWASP Top 10, NIST SP 800-53, ISO 27001:2022, and PCI DSS v4.0 — four frameworks with 11 mapping dicts. However, these mappings are consumed only by internal calls. No automated output artifact ties findings to compliance evidence in a format consumable by auditors, GRC teams, or incident-response workflows.

1.  **Compliance Coverage Report Generator**
    *   **Status**: 🟢 **COMPLETE.** `build_compliance_report(findings)` is imported and called inside `build_summary()` in `src/reporting/pipeline.py` (line 187–189). The result is embedded in the summary payload (`"compliance": compliance_report`, line 198) and persisted alongside the HTML report. `src/pipeline/services/output_store.py` wires `compliance_coverage.json` and `compliance_maturity.json` (lines 218–233) into the standard artifact payload; `src/pipeline/services/pipeline_orchestrator/stages/reporting.py` uploads both at lines 264–265. Acceptance: ✅ a fresh compliance artifact is produced by every scan.

2.  **Pass/Fail Control Maturity Scoring**
    *   **Status**: ❌ NOT STARTED. Current output is a flat coverage map showing which controls were *touched*, not whether they are *under control*.
    *   **Hardening**: Define `ControlMaturity(Enum)` in `src/reporting/compliance_maturity.py` with bands: `FAIL` (open critical finding against control), `AT_RISK` (open high finding), `PARTIAL` (open medium finding / no finding but partial compensating control detected), `PASS` (no open finding of any severity). Produce per-target `compliance_maturity.json` alongside the coverage artifact. Wire `FAIL` and `AT_RISK` items into the notification system (`src/infrastructure/notifications/`) so GRC stakeholders receive automated alerts. Acceptance: maturity file shows at least one `FAIL` band for any target carrying an unresolved critical finding.

3.  **SOC 2 / PCI-DSS Attestation PDF Export**
     *   **Status**: 🟢 COMPLETE.
     *   `src/reporting/compliance_pdf.py` generates a two-part document: (a) executive summary with critical/high findings, framework IDs, and remediation SLA table; (b) detailed evidence pack with per-finding snapshots and audit-log excerpts.
     *   FastAPI route `GET /api/reports/compliance/pdf?target=<name>` in `src/dashboard/fastapi/routers/reports.py` serves the generated PDF.

---

## 🌐 Phase 7: Multi-Tenant Isolation & Federated Mesh
**Goal**: The `Ghost-Actor Mesh` (`src/core/frontier/ghost_actor.py`, `src/infrastructure/mesh/`) is single-tenant — every node sees every finding, Redis keys are shared across all concurrent scans, and no per-client namespace boundary exists. This blocks commercial/consultancy use where multiple clients' scans must be strictly separated in both data and compute.

1.  **Redis Key Namespacing Layer**
    *   **Status**: ❌ NOT STARTED. `src/infrastructure/queue/redis_client.py` and `src/learning/repositories/redis_fp_repo.py` write to flat top-level keys like `mesh.learning.fp_patterns`, `pipeline.progress.*`, `security-events`, `pipeline.state.*`.
    *   **Hardening**: Introduce `TenantContext` Pydantic model in `src/core/models/tenant.py` (fields: `tenant_id: str`, `namespace_prefix: str`, `allowed_networks: list[str]`). Update `RedisClient` in `src/infrastructure/queue/redis_client.py` to accept an optional `tenant_id` parameter and prepend `"{tenant_id}:"` to every key operation. Update all concurrent callers (`FPTracker`, `MeshSync`, `JobQueue`, `CheckpointManager`) to read `tenant_id` from `PipelineContext`. Acceptance: two concurrent runs with different `tenant_id` values read/write disjoint Redis key sets with zero cross-contamination verified by an integration test.

2.  **RBAC Dashboard Layer with Tenant Scoping**
    *   **Status**: 🟡 PARTIAL. `AuthManager` (`src/infrastructure/security/auth/manager.py`) supports roles (`VIEWER`, `ADMIN`, `WORKER`), and `require_auth` / `require_admin` dependencies exist in `src/dashboard/fastapi/dependencies.py`. No per-target or per-tenant scope filtering exists on any list endpoint.
    *   **Hardening**: Extend `AuthManager.get_current_user()` to return a `CurrentUser` Pydantic model with fields `user_id`, `role`, `tenant_id`, `tenant_scope` (either `GLOBAL` or a list of allowed target hosts). Filter `GET /api/targets`, `GET /api/findings`, and `GET /api/jobs` in their respective routers (`targets.py`, `findings.py`) by the caller's `tenant_id`. Add integration tests that assert a `VIEWER` user scoped to tenant A receives an empty list when requesting tenant B targets. Acceptance: tenant isolation test suite passes in `tests/integration/test_tenant_isolation.py`.

3.  **Cross-Tenant Playbook Isolation**
    *   **Status**: ❌ NOT STARTED. Nuclei templates, WAF evasion profiles (`src/core/frontier/chameleon.py`), and exploit playbooks are loaded globally with no tenant-scoped directory isolation.
    *   **Hardening**: Scope all `nuclei` template path resolution by `tenant_id` — each tenant gets an isolated `nuclei/` sub-directory under `<output_root>/<tenant_id>/`. Scope `Chameleon` header mutation profiles by `tenant_id` so concurrent tenants running identical payloads trace independent header sets. Add `tenant_id` to the `StageInput` contract so isolation is preserved across every DAG stage. Acceptance: two tenants using the same chameleon profile mutate headers concurrently without crosstalk, verified by a concurrent-execution integration test.

---

## 🛡️ Phase 8: Supply Chain Integrity & SBOM Automation
**Goal**: The CI pipeline (`ci.yml`) runs `pip-audit`, `safety`, `semgrep`, and `trivy` — but there is no automated software bill of materials (SBOM) workflow with attestation, no nuclei template provenance check, and no dependency pinning enforcement gate. Supply chain attacks (compromised pip packages, typosquanted nuclei templates) are not currently guarded against.

1.  **CycloneDX SBOM Diff Gate in CI**
    *   **Status**: ❌ NOT STARTED. `ci.yml` generates an SBOM artifact using `cyclonedx-bom` but does not compare it against a previous baseline or enforce a "no-new-critical" gate. Anyone can silently introduce a vulnerable dependency.
    *   **Hardening**: Add `SBOM Diff` job to `.github/workflows/ci.yml`. Store the last-approved SBOM in `configs/sbom-baseline.json`. On each PR, run `syft . -o cyclonedx-json > sbom-current.json`, diff against the baseline with `grype sbom-current.json --fail-on high`, and fail the job if any new package has a `cvssScore ≥ 7.0`. Update the baseline only via a manual maintainer merge to `main`. Acceptance: a PR introducing `requests==2.99.0` (hypothetical vulnerable version) fails CI with a clear SBOM diff report.

2.  **Nuclei Template Provenance Validation**
    *   **Status**: ❌ NOT STARTED. `NUCLEI_TEMPLATE_PATH` in `.env` defaults to `~/.nuclei-templates` with no integrity verification. A compromised `~/.nuclei-templates/` directory would silently inject malicious scan logic.
    *   **Hardening**: Add `src/recon/nuclei_template_validation.py` — on pipeline startup, compute SHA-256 hashes of every `.yaml` template under `NUCLEI_TEMPLATE_PATH` (filtering the top 40 k highest-priority templates to avoid start-up overhead), compare against a signed manifest stored in `configs/nuclei_manifest.json`. Store the manifest as an Ed25519 signature over the JSON hash-map. Fail fast on any mismatch and log the specific filename + expected vs. actual hash. Acceptance: tampering a single nuclei template file causes an immediate pipeline abort with the filename and hash mismatch in the log output.

3.  **Dependency Pinning Policy Enforcement**
    *   **Status**: ❌ NOT STARTED. `pyproject.toml` uses open semver ranges (`httpx>=0.28.0,<1.0.0`, `fastapi>=0.115.0,<1.0.0`) rather than pinned versions. A new upstream release introducing a CVE would be picked up silently in every `pip install`.
    *   **Hardening**: Add `ci.yml` job `dependency-pins` that runs `pip-compile --generate-hashes` against `pyproject.toml` and verifies `requirements-lock.txt` matches exactly. Fail if drift is detected. In the `security` job, raise `pip-audit` from informational to `error` for any `HIGH`/`CRITICAL` CVE in direct (not transitive) dependencies. Acceptance: loosening a version range in `pyproject.toml` without an accompanying `requirements-lock.txt` update triggers a CI failure before merge.

---

## 🔁 Phase 9: Closed-Loop Exploit Remediation Verification
**Goal**: AEVE (`src/execution/exploiters/aeve.py`) transitions findings through `CANDIDATE → VERIFYING → VERIFIED_TP / FALSE_POSITIVE`, but there is no automated re-verification path after a remediation ticket is filed and closed — the pipeline treats the issue as "handled" and stops tracking it, leaving a regression blind spot for weeks or months.

1.  **Remediation Re-Scan Firewall**
    *   **Status**: ❌ NOT STARTED. No reinvocation strategy exists for previously-verified findings.
    *   **Hardening**: Add `src/execution/remediators/remediation_scanner.py` — accepts a `verified_finding_id`, looks up the original finding in `<output>/findings/findings.json`, extracts the affected endpoint and payload, re-targets only that endpoint with the same AEVE payload, and transitions the stored status to `REGRESSED` or `REMEDIATED`. Triggered by `POST /api/remediated/{finding_id}/verify`, guarded by an adaptive cooldown defaulting to 72 h (configurable in `configs/config.example.json` under `remediation.cooldown_hours`). Acceptance: running a remediation verification scan on a confirmed-fixed IDOR endpoint returns `REGRESSED` or `REMEDIATED` within two pipeline stages.

2.  **Recurring False-Positive Re-Evaluation Watchlist**
     *   **Status**: 🟢 COMPLETE.
     *   `src/recon/fp_watchlist.py` provides `FPWatchlistManager` that serializes `FALSE_POSITIVE` findings to `<output>/regression-watchlist.json` on every run completion.
     *   `get_watchlist_urls()` returns URLs for elevated-confidence re-injection via `build_nuclei_plan()`.
     *   `check_reemergence()` notifies via `NotificationManager` on any re-emergence.

3.  **Exploit Chain Drift Detection**
    *   **Status**: ⚠️ FRAGMENTED. `VulnCorrelationEngine` (`src/intelligence/correlation/attack_chain_correlator.py`) builds attack chains and `src/reporting/pipeline.py` stores chain artifacts. No mechanism compares chain shapes between runs to detect new exposures or remediated paths.
    *   **Hardening**: Add `src/intelligence/correlation/chain_diff_engine.py` — canonicalizes each run's attack chain as a sorted graph-node list, then computes Jaccard similarity per chain node. Flag nodes present in Run B but absent from Run A as *new exposure*; flag Run A nodes absent from Run B as *closed chain* (remediated path). Expose via `GET /api/chains/diff?from_run=<run_id>&to_run=<run_id>` and add a Chain Drift tile to `RiskScorePage.tsx`. Acceptance: a chain diff showing ≥10% node churn per 30-day window surfaces on the dashboard Chains page.

---

## 📡 Phase 10: API-Led Governance & Developer Experience
**Goal**: The pipeline exposes 30+ FastAPI endpoints but has no OpenAPI-generated contract documentation, no request/response schema stability gate, and no developer tooling for extending the analyzer without touching core code.

1.  **OpenAPI Contract Quality Gate**
    *   **Status**: ❌ NOT STARTED. FastAPI auto-generates `/docs` and `/openapi.json`, but the generated schemas are unstructured prose. No CI gate enforces schema stability — any endpoint change silently breaks consumer integrations.
    *   **Hardening**: Add `scripts/validate_openapi.py` — starts the dashboard in the background, downloads `openapi.json`, runs `openapi-spec-validator`, then diffs against `configs/openapi-baseline.json` using `jsondiff`. Fail CI if breaking changes are detected without a `.openapi-bump.md` changelog entry in the same PR. The bump entry documents the changed path, operation, and a justification field. Acceptance: removing a response field from any production endpoint causes the CI job to fail before merge.

2.  **Plugin Scaffold CLI (`cyber plugin new`)**
    *   **Status**: ❌ NOT STARTED. The plugin registry (`src/core/plugins.py`) requires developers to manually add boilerplate imports, `@register_plugin` decorators, contract protocol classes, and Zod schema updates across 3–4 files.
    *   **Hardening**: Add `plugin new` subcommand to `src/cli.py` with interactive prompts (`rich.prompt.Prompt`) for plugin name, category, and I/O contract fields. Template-generate `src/recon/sources/<name>.py`, `src/core/contracts/<name>.py`, and `frontend/src/api/schemas/<name>.ts` from Jinja2 templates stored in `configs/plugin_templates/`. Run `ruff check` and `mypy` before the CLI confirms. Write the new plugin name to `configs/plugins/registry.json` so `list_plugins()` discovers it automatically. Acceptance: running `cyber plugin new` produces a compilable, type-checked plugin in <60 s without manual file edits.

3.  **Local Dev Self-Check (`cyber doctor`)**
     *   **Status**: 🟢 COMPLETE.
     *   Added `doctor` subcommand to `src/cli.py` under the `system` area with 5 health checks (Python version >=3.14, system binaries, Redis connectivity, .env file validity, config integrity).

---

## 🎭 Phase 11: Playwright Accessibility & Frontend Security Codex
**Goal**: Frontend E2E coverage (`frontend/tests/e2e/`) and `playwright.config.ts` exist, but no E2E suite validates WCAG 2.2 AA conformance or screens for common frontend security anti-patterns (`dangerouslySetInnerHTML`, missing CSP headers in the dist bundle, hardcoded secrets).

1.  **WCAG 2.2 AA E2E Audit Suite**
    *   **Status**: ❌ NOT STARTED. The E2E suite covers functional flows (findings timeline, job monitoring) but asserts nothing about accessibility conformance.
    *   **Hardening**: Add `frontend/tests/e2e/a11y.spec.ts` using `@playwright/test` + `@axe-core/playwright`. Assert A-level success criteria: skip-links are present and focusable on every page, focus-visible rings on all interactive controls, ARIA labels on all icon-only buttons, `role` attributes on navigation landmarks, and color-contrast ratio ≥4.5:1 for body text. Fail the `test:e2e` CI job (with `npx playwright test --reporter=... tests/e2e/a11y.spec.ts`) on any A-level violation. Acceptance: an `<a>` tag missing an `href` or a form input missing a label triggers a playwright test failure before merge.

2.  **Bundle Hash Attestation (Prevent Secret Leak in Dist)**
    *   **Status**: ❌ NOT STARTED. The build emits `frontend/dist/assets/*.js` bundles with no attestation that they match the published TypeScript source. An inadvertently committed `console.log(process.env.SECRET_KEY)` or `dangerouslySetInnerHTML` block would ship to production unnoticed.
    *   **Hardening**: Add `scripts/verify_bundle_hashes.sh` that computes `sha256` of every `frontend/dist/assets/*.js` bundle after `npm run build` and verifies against baselines stored in `configs/bundle_baselines.json`. Fail the `build` CI job if the final bundle deviates. Baseline entries are updated only via a manual `.openapi-bump.md`-style changelog commit. Acceptance: injecting a `console.log(process.env.*)` snippet into any page component causes a bundle hash mismatch and a CI failure.

3.  **CSRF Token Propagation in Dashboard Forms**
    *   **Status**: ⚠️ PARTIAL. `csrf` detection exists in `src/reporting/compliance_mapping.py` → `A01:2021-Broken Access Control`, and validators exist in `src/execution/validators/validators/`, but all dashboard forms at `frontend/src/pages/*.tsx` use plain `fetch`/`axios` calls without anti-CSRF tokens.
    *   **Hardening**: On app bootstrap, call `GET /api/csrf-token` to obtain a per-session token. Audit all `fetch` and `axios` POST/PUT/DELETE calls across `frontend/src/pages/` and `frontend/src/api/`, adding `X-CSRF-Token` header sourced from the bootstrap call. Wire a Playwright route interceptor that marks the `test:e2e` job as failed if any mutating request in the trace session is sent without the header. Acceptance: a Playwright trace shows `X-CSRF-Token` present on every mutating dashboard mutation.

---

## Success Criteria

Per-phase acceptance tests must pass on the `main` branch before a sprint is considered complete. All new endpoints return OpenAPI-validated schemas, all new Python modules pass `ruff check --select S` (Bandit security rules) and `mypy --strict`, and all new frontend pages pass `npm run check:types` and `npm run lint`.

Integration tests for new learning/chain features use `httpx.AsyncClient` against a locally-started dashboard. Mutation tests (`mutmut`) cover all new stage runner logic. SBOM and nuclei provenance jobs gate the `main` branch CI for any PR that touches `pyproject.toml`, `configs/nuclei_manifest.json`, or `requirements-lock.txt`.
