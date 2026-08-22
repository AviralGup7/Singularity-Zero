# Dead / Unused / Duplicate Code Audit — Reconciled Against Current HEAD

**Original audit commit:** `16b5ea77`  
**Reconciled against:** `13b7df87` (`main`) and subsequent local wiring  
**Methodology of original audit:** static grep/read, no runtime coverage, tests not executed  
**This reconciliation:** current-tree existence, import/registry/CLI/config/test/doc traces, then KEEP unless obsolescence is proven

The original report is a **candidate inventory**, not an authorization to delete. Previous cleanup (`dc25adf5`, `3e89806f`) plus findings/jobs/session restoration already handled the confirmed-safe frontend dead code.

---

## Reconciled totals (original candidates)

| Outcome | Count (approx) | Meaning |
|---|---:|---|
| Already resolved | 6 | Deleted or superseded since `16b5ea77` |
| False positive | 40+ | Static grep missed registry, lazy `__getattr__`, frontend API, or later wiring |
| No longer dead | 35+ | Restored and imported after the audit |
| Still present, KEEP / optional | 50+ | Security, plugin, public API, future subsystem, or both-acceptable pair |
| Rewire candidates | 4 | Disconnected but useful; wired as optional settings this pass |
| Safe delete | 0 | Nothing proven obsolete without losing a capability |

---

## Phase 0 — Current state at start of this pass

- Branch: `main`
- HEAD: `13b7df87` `fix: project lists, remediation units, access logs`
- `16b5ea77` is an ancestor (60 commits later)
- Working tree was clean
- Existing stashes preserved (`stash@{0}` … `stash@{5}`); none dropped or popped
- Prior cleanup and feature restoration are on this branch

---

## Phase 1 — Candidate table (abridged)

Classification key: **A** already resolved · **B** still present/suspicious · **C** no longer dead · **D** false positive · **E** architectural / keep

### Backend entire modules (audit §1)

| path | original | HEAD | runtime / dynamic | tests | config | replacement | new class | action | conf | risk |
|---|---|---|---|---|---|---|---|---|---|---|
| `src/pipeline/analyst_notes.py` | dead module | present | registered in `startup_registration` + notes/cockpit routers via protocol registry | notes API | startup | none | **D** | KEEP | high | high if deleted |
| `src/execution/auth/auth_flow_runner.py` | dead module | present | public `AuthFlowRunner` is `auth_flow.py`; this file is a richer YAML runner | none for this file | none | `auth_flow.py` (different) | **E** | KEEP both (optional auth style) | high | high |
| `src/exploitation/takeover/` | dead package | present | lazy `__getattr__` on `src.exploitation` | `tests/unit/exploitation/test_takeover_*` | fingerprints.json | exposure checkers (weaker) | **D/E** | KEEP | high | high |
| `src/recon/collectors/crawler.py` | dead | present | `CrawlerProvider` protocol + `DefaultCrawlerProvider` | `scripts/run_crawler_unit_test.py` | recon | none | **E** | KEEP | med | med |
| `src/recon/collectors/aggregator_stream.py` | dead | present | recon collector | `tests/unit/recon/test_aggregator_stream.py` | README | none | **C/D** | KEEP | high | med |
| `src/execution/waf_probe_adapter.py` | dead | present | protocol docstring; companion to WAF strategies | none | waf_evasion config mentioned | `detection/waf/probe_adapter.py` (different) | **E** | KEEP both | med | high |
| `src/core/plugins/framework.py` | dead | present | unused vs `plugins/registry.py` (the exported one) | conftest mentions registry | none | `registry.py` (different contract) | **E** | KEEP | med | med |
| `src/core/frontier/plugins/xxe_unsafe_xml_parser.py` | dead | present | filesystem plugin discovery | `tests/unit/analysis/test_xxe_plugins.py` | plugin dir | none | **D** | KEEP | high | high |
| `src/execution/templates/render.py` | dead | present | unused; `steps/template.py` is the imported renderer | none | none | `steps/template.py` | **E** | KEEP (tiny helper) | med | low |
| `src/cache/__init__.py` | dead package | present | unused 14-line facade over unified cache | none | none | `pipeline.unified_cache` | **E** | KEEP public facade | med | low |

### Backend test-only / small packages (audit §2)

All **E / KEEP**: `sandbox`, `console`, `checkpoint`, `mesh`, `realtime`, `exploitation/capabilities`. Tests and/or public package APIs exist. “Only tests import it” is not obsolescence. `src/kernel` + `src/core_domain` were later deleted (unused hexagonal shell).

### Backend “dead symbols” files (audit §3)

| path | new class | action | why |
|---|---|---|---|
| Active analysis (`csp_bypass`, `dom_xss_browser`, `grpc_fuzzer`, `graphql*`, `oauth_testing`, `xxe_detection`, `probe_template`) | **E** | KEEP | Security testing capability; not currently enabled ≠ dead |
| `actor_race.py` vs `actor_tester.py` | **E** | KEEP both | Near-duplicate, not identical; package exports `actor_tester` |
| `api_security_assessor.py`, `secrets_scanner.py`, `detector_mass_assignment.py` | **E** | KEEP | Documented as awaiting pipeline integration (`docs/GAP_ANALYSIS.md`) |
| `differential_prober.py`, `semantic_dedup.py` | **E** | KEEP | Intelligence helpers |
| `src/learning/repositories/*` | **D/E** | KEEP cluster | Learning is live; `telemetry_store` + `redis_fp_repo` used; others are schema/API |
| `notifications/filters.py`, `escalation.py` | **E** | KEEP | Notification package is used by console |
| Dashboard controls/services (`event_handlers`, `widgets`, `dashboard_services`, `launch_service`, …) | **D** | KEEP | Facades imported by `form_specs`, services package, architecture tests |
| `http_metrics.py` | **C** | REWIRE | Documented middleware; now optional via `ENABLE_HTTP_METRICS` |
| `detection/waf/probe_adapter.py` | **E** | KEEP | Parallel WAF adapter (see execution copy) |
| `detection/plugins_view.py`, `detection/timing/*` | **E** | KEEP | Detection capability |
| `frontier/merge.py` | **E** | KEEP | Frontier package is tested |
| `intel/metrics.py`, `intel/report.py` | **E** | KEEP | `src.intel` is used by console |
| `learning/thresholds.py` | **E** | KEEP | Learning subsystem |
| `src/auth/demo.py` | **D** | KEEP | `console/handlers/session.py` imports `demo_card` |

### APIs (audit §5)

| endpoint / router | registered? | frontend? | 501? | action |
|---|---|---|---|---|
| `POST /api/triage/.../ai-review` | yes | `frontend/src/api/triage.ts` | yes, module removed | KEEP (contract) |
| `GET /api/findings/{id}/explain` | yes | `frontend/src/api/findings.ts` | stub | KEEP |
| `GET /api/findings/{id}/ai-explain` | yes | same | stub | KEEP |
| `GET /api/reports/ai-summary` | yes | `frontend/src/api/reports.ts` | 501 | KEEP |
| `/api/assignments` | yes (`routers/__init__.py`) | not current UI | real store | KEEP public API |
| `/launcher/{job_id}/{filename}` | yes | artifact serving | no | KEEP (auth + tenant) |
| `/api/compliance` | yes | access-logs/custody also exist separately | real sqlite | KEEP |
| `POST /api/jobs` + `POST /api/jobs/start` | yes, same handler | UI uses `/start` | no | KEEP dual route |
| cockpit `edges.py` | router included; **no route decorators** | helpers unused by `nodes.py` | n/a | KEEP helpers / DEFER empty router |

### Barrels / entry points / specs

- Package `__init__.py` barrels: **KEEP** (public/internal APIs, lazy facades).
- `src/main.py`: sample `python -m src.main` pipeline demo; excluded from mypy; **KEEP**.
- `start_backend.py`: local uvicorn entry; listed in pyproject mypy/coverage excludes; **KEEP**. Canonical: `cyber start dashboard` / `cyber-dashboard-fastapi`.
- `src/analysis/intelligence/findings/specs/` (~88 files): **LIVE**. `get_all_specs()` is consumed by `findings/_misc_merge.py`. **Do not delete.** Original audit’s import analysis was a false negative.

### Frontend (audit §7–10)

Almost the entire “dead components” list is **C / no longer dead** after restoration:

SessionLock, useSessionTimeout, FindingsKanbanView, FindingsTableView, StartJobForm + wizard steps, FindingComparisonPanel, CVSSDetail, ThreatIntel, PII, RemediationTracker, GapAnalysisStats, RunDiffViewer, ReconResults, ErrorOverlayView, useRealtimeStream, useFocusManagement, useKeyboardShortcuts, FocusTrap, FormField, CopyButton, CinematicIntro, DashboardTrendCharts, PerformanceDashboard, InstallPrompt, etc.

Already resolved (absent now): `HealthIndicator.tsx`, `LogViewer.tsx`, `AccessibleEmoji.tsx`, `useDashboardData.ts`, `useDebouncedPersist.ts`, `useExport.tsx`.

Still present, unused in the live tree, **KEEP / optional**:

| item | decision |
|---|---|
| `LivePipelineStatus` | Wired behind `features.livePipelineStatus` (default off). Complements `ScanStatusBar`. |
| `WebVitalsDashboard` | Wired when `features.clientPerformance` is on (with `PerformanceDashboard`). |
| `RoleGates.tsx` | Parallel to `RequireRole` in AuthContext. KEEP both. |
| `FindingsFilterBar` | Do **not** replace working filters. KEEP unused. |
| `useBulkActions` | Table already has bulk UI. KEEP hook. |
| `useVisibilityAPI` / `VisibilityIndicator` | KEEP; tab-hidden banner is not useful while visible. |
| `DataTable` | Shared UI primitive + tests. KEEP. |
| Stories / hero.png | Storybook fixtures. KEEP. |
| Cross-layer FE/BE duplicates (export, threat intel, scope, PII, time, roles, audit) | Intentional (offline UI vs authoritative backend). Do **not** merge. |

### Tests / scripts / docs (audit §11–12)

“Not in CI” ≠ delete. Keep security/audit scripts, import smoke, benchmarks, migrations, windows/unix launchers. Stale route lists in `docs/frontend.md` remain documentation debt (pages live in hubs); not rewritten just to hide architecture.

---

## Safe deletions

**None executed.**

No candidate was proven obsolete without also being:

- a security capability,
- a public/compatibility API,
- a plugin/discovery target,
- a restored UI feature,
- or one of two acceptable implementations.

---

## Preserved capabilities

- Analyst notes (protocol-registered)
- Auth flow runners (both implementations)
- Subdomain takeover engine + fingerprints
- Recon crawler and aggregator stream
- WAF probe adapters (execution + detection)
- Plugin framework + XXE sandbox plugin
- GraphQL / gRPC / OAuth / XXE / race / CSP / DOM XSS analysis modules
- Finding spec registry (~88 specs, merge-time lookup)
- Learning repositories + live learning router
- Assignments, launcher artifacts, compliance persistence
- 501 AI stubs still called by frontend API clients
- `src.main` / `start_backend.py` developer entry points
- All frontend restored surfaces and optional feature flags

---

## API cleanup

| endpoint | status |
|---|---|
| AI review / explain / ai-explain / ai-summary | **Still supported as 501 stubs** (frontend clients + OpenAPI) |
| Assignments / launcher / compliance | **Still supported** |
| Dual `POST /api/jobs` | **Still supported** (compatibility) |
| Nothing removed | — |

---

## Scripts / tests

- No scripts archived or deleted
- Added: `frontend/src/tests/unit/auditReconcile.test.ts`
- Added: `tests/unit/dashboard/test_http_metrics_policy.py`
- Extended: `frontend/src/tests/unit/deferredWiring.test.ts`

---

## Documentation

This file is the reconciliation record. Route overview docs were **not** rewritten to pretend unused hubs are gone; several still exist as tabs inside parent pages.

---

## Remaining debt

**None.** Closed in the follow-up pass:

1. Optional analysis modules are registered in `ACTIVE_PLUGIN_SPECS` with `enabled_by_default=False` and bound through `src/analysis/optional_probes.py`.
2. Auth runners are an operator choice via `AUTH_FLOW_ENGINE` (`builtin` | `yaml`).
3. Cockpit `edges.py` owns graph helpers; `nodes.py` imports them; `GET /api/cockpit/edges` is live.
4. Compact Findings filter chrome is optional (`compactFindingsFilters`); tactical filters stay default. Bulk selection helper is shared.
5. `RoleGate` (hierarchy) wraps Experimental settings; `RequireRole` stays exact-match.
6. Scripts outside CI remain tooling, not debt.
7. Cross-layer FE/BE duplication is intentional and closed as such.
8. Notification filters/escalation, intel metrics/report, detection plugin rows, and learning `suggested_threshold` are wired into their live packages.

---

## Validation

See the commit message / final report in the agent session for exact command results.

---

## Git

Focused commits for this pass:

- `feat: optional live pipeline status and web vitals panels`
- `feat: optional HTTP metrics middleware`
- `docs: reconcile dead-code audit against current HEAD`

No reset/revert of existing work. Stashes untouched.
