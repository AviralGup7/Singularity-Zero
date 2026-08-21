# Modularization candidates

Inventory of subsystems that already exist as *names* but are **tangled**,
**duplicated**, or **half-wired**. Each one deserves its own package with a
small public API, its own tests, and no FastAPI / React / pipeline imports
leaking inward.

Rule of thumb: if two folders share a noun (`frontier`, `circuit_breaker`,
`intelligence`, `exploiters`, `jobs`, `notifications`) they are mixed up.

Allowed dependencies are listed as *this module may import*. Everything else
is forbidden.

---

## How to read this

| Tag | Meaning |
|---|---|
| **Facade** | Package exists, but it re-exports or lazily imports another package |
| **Split** | Same concern lives in 2+ top-level trees |
| **Unwired** | Code exists, pipeline/UI does not call it as a first-class stage |
| **Dump** | Real logic, but dumped into a neighbor (dashboard, analysis, pages/) |
| **Shell** | Directory is almost empty; easy to confuse with the real module |

Priority: **P0** extract or you keep shipping bugs. **P1** extract next.
**P2** clean later.

---

## P0 — actively colliding

### 1. Job lifecycle  — Dump

**Mixed with:** `src/dashboard/job_*.py`, `pipeline_jobs.py`,
`src/dashboard/fastapi/routers/jobs/`, frontend `jobStore` + 5 `useJob*` hooks.

**Why it deserves its own module:** Jobs are the product’s unit of work.
Today the store, state machine, snapshot, SSE, and HTTP handlers all live
under the dashboard package. Pipeline code and the UI both reach through
FastAPI-shaped types. That is how demo-login 401s and “is the job running?”
bugs leak into the SPA.

**Independent module:** `src/jobs/`

| Public API | Owns |
|---|---|
| `JobStore`, `JobState`, `JobSnapshot` | persistence + transitions |
| `JobEvents` (queued/start/progress/done) | bus payload, not HTTP |
| `JobQuery` | list/get without FastAPI |

- May import: `src.core.models`, `src.core.events`
- Must not import: `src.dashboard`, FastAPI, React-era DTOs
- Dashboard keeps only routers that call `src.jobs`

Frontend twin: `frontend/src/features/jobs/` (page + store + SSE hook).
Today JobsPage is a 200-line page; hooks are global.

### 2. Notifications  — Split + Dump

**Mixed with:** `src/infrastructure/notifications/`,
`src/dashboard/fastapi/routers/notifications.py`,
`routers/jobs/notifications.py`, `lifespan_notifications.py`,
`pipeline/self_healing` → NotificationManager,
frontend `useNotifications` (JWT-gated).

**Why:** In-app toasts, Slack/email/webhooks, job SSE, and self-healing
alerts share a name and a 401 path. Demo sessions have no token; the UI
still hits `/api/notifications`. That is a module-boundary failure, not a
theming bug.

**Independent module:** `src/notifications/`

- `InAppInbox` (requires a session, not a JWT)
- `ChannelSink` (slack/email/webhook)
- `NotificationPolicy.should_fetch(session)` — demo/guest skip
- May import: `src.core`, auth *session* type only
- Must not import: FastAPI routers, pipeline orchestrator

Frontend: `frontend/src/features/notifications/` owning the hook, bell, SSE.

### 3. Auth / session  — Dump (and config-locked)

**Mixed with:** `src/dashboard/fastapi/security.py`, `middleware.py`,
`config.py` (agent-do-not-auto-modify), guest token, demo Sign In,
frontend `authStore` + `AuthContext` + LoginPage.

**Why:** Demo analyst, guest, API key, and JWT are four session kinds
inlined into the dashboard app. ENABLE_API_SECURITY vs
DASHBOARD_AUTH_DISABLED is a process-env tangle. Login UX and API auth
cannot evolve independently.

**Independent module:** `src/auth/`

- `Session` = `{kind: demo|guest|api_key|jwt, subject, roles, capabilities}`
- `Authenticator` protocol + four adapters
- Capability `viewAuditLogs` lives here, not in LoginPage
- May import: `src.core.security`
- Must not import: SPA, jobs, notifications

Frontend: `frontend/src/features/auth/` (login, store, route guard).

### 4. Detection runtime  — Facade

**Mixed with:** `src/detection/registry.py` imports
`src.analysis.plugin_registration` and `src.analysis.plugins`.
`src/analysis` imports `src.detection` for findings merge.
GAP: “detection/ is a thin facade over analysis/”.

**Why:** You cannot tell whether a probe is a detector, an analyzer, or a
plugin spec. Architecture tests assert the two registries are *equal*,
which freezes the tangle.

**Independent module:** keep `src/detection/` but invert the dependency.

- Detection owns: WAF, AST, browser, timing, `DetectionPlugin` contract
- Analysis *registers* bindings via `src.core.plugins`
- Detection must not import `src.analysis`
- Analysis must not import `src.detection.registry`

### 5. Circuit breaker / retry  — Split

**Mixed with:** `src/pipeline/services/circuit_breaker.py` **and**
`src/pipeline/retry/circuit_breaker.py`. TODO P1.1: state is not
persisted. P0.3 Retry-After override is unstarted.

**Why:** Two breakers, one scheduler. HALF_OPEN probes are not in the
idle loop. Easy to “fix the wrong file”.

**Independent module:** `src/resilience/`

- `RetryPolicy`, `CircuitBreaker`, `RetryAfterParser`
- Persistent store (SQLite/Redis) inside this package
- Pipeline scheduler *uses* it; does not own it

---

## P1 — same noun, two (or three) homes

### 6. Frontier / WAL / Ghost actor  — Split

| Tree | What it actually holds |
|---|---|
| `src/core/frontier/` | LWW state, bloom, VFS isolation, DRL stub, WAF patterns |
| `src/infrastructure/frontier/` | WAL, ghost actor, vault, bloom mesh |
| `src/execution/frontier/` | chameleon evasion, wasm |

**Independent module:** `src/frontier/` (CRDT + WAL + mesh snapshots).
Evasion and WASM do not belong here — they rode along because of the
folder name.

### 7. Checkpoint / recovery  — Split

- `src/core/checkpoint/` (manager, WAL-aware recovery)
- `src/infrastructure/checkpoint/distributed.py`
- pipeline `--resume-from` / `--wal-replay`

**Independent module:** `src/checkpoint/` used by pipeline runtime.
Infrastructure only supplies the distributed backend.

### 8. Exploitation vs execution vs `core/exploiters`  — Split

| Tree | Should own |
|---|---|
| `src/exploitation/` | engines + payloads (HTTP, SSRF, takeover) |
| `src/execution/` | *how* a PoC runs (WASM/AEVE, validators, steps) |
| `src/core/exploiters/` | **should not exist** — move to execution |

GAP: AEVE is not connected to wasmtime. That wiring is blocked by the
split. Target: `src/execution/sandbox` as the only PoC runner.

### 9. Fuzzing vs `core.mutation_engine`  — Dump

Recent CI: “keep core protocol registry free of fuzzing imports”.
Fuzzing still pulls `src.core.mutation_engine`, `src.core.session`.
JSON AST mutator lives in fuzzing; other JSON mutations live under
`analysis/response` and `analysis/intelligence`.

**Independent module:** `src/fuzzing/` owns all mutators.
Core keeps only URL/IP validation. Analysis calls fuzzing via a
`Mutator` protocol, not by importing generators.

### 10. Three “intelligence” packages  — Split

| Package | Real job |
|---|---|
| `src/analysis/intelligence/` | in-scan scoring, 88 finding *specs*, graphs |
| `src/intelligence/` | TI feeds, severity model, swarm stub |
| `src/learning/` | FP tracker, feedback loop, threshold tuner |

Rename to stop collisions:

- `src/analysis/scoring/` (in-scan)
- `src/intel/` (feeds + correlation + severity model)
- `src/learning/` (closed loop only)

GAP listed VT/OTX as missing; the clients **exist**
(`feeds/virustotal.py`, `feeds/otx.py`) but are not a pipeline stage.
That is an unwired module, not a missing file.

### 11. Cache  — Split

`src/pipeline/cache.py`, `cache_backend.py`, `unified_cache/`,
dashboard `routers/cache.py`, frontend CacheManagementPage.

**Independent module:** `src/cache/` (SQLite + file + SWR).
Pipeline and dashboard become clients. One place for stage partitioning.

### 12. Realtime (WS + SSE)  — Split

`src/websocket_server/` vs `dashboard/fastapi/lifespan_websocket.py` vs
jobs SSE vs notifications stream.

**Independent module:** `src/realtime/`

- rooms, backpressure, heartbeat
- FastAPI mounts it; does not implement it

### 13. Mesh / Bloom  — Split

`core/frontier/bloom.py`, `infrastructure/health/bloom_mesh.py`,
`infrastructure/mesh/`, dashboard `routers/bloom.py` + MeshHealthPage.

**Independent module:** `src/mesh/` (membership + bloom sync + health).
Dashboard is a viewer.

---

## P1 — frontend feature slices (only `findings` is a feature today)

Everything else is a page in `frontend/src/pages/` plus stray components.
These collide with each other in AppLayout, hooks/, and stores/.

| Extract to | Today |
|---|---|
| `features/auth` | LoginPage, authStore, AuthContext, RouteGuard |
| `features/jobs` | JobsPage, JobDetailPage, jobStore, useJobMonitor* |
| `features/targets` | TargetsPage, TargetComparison, scopeStore |
| `features/theme` | themeStore, ThemeContext, ThemeSection, NightCityHud, night-city.css |
| `features/cockpit` | CockpitPage + pages/cockpit + components/cockpit |
| `features/pipeline` | PipelineOverview, SelfHealing, LivePipelineStatus |
| `features/notifications` | useNotifications + header bell |
| `features/settings` | SettingsPage dump of every concern |

`features/findings/` is the template: page + components + hooks in one tree.

Night City is the current example of a feature living in layout CSS:
without `features/theme`, HUD/art/spa mounts keep getting “fixed” in the
wrong layer.

---

## P2 — shells, dumps, unwired catalogs

### 14. `src/kernel` + `src/core_domain`  — Shell

~108 lines total. Easy to import instead of `src.core.config`.
Either delete and alias, or make `kernel` the *only* configuration
entry (typed config + feature flags) and stop growing `core/config`.

### 15. `src/analysis/checks` vs `src/analysis/active|passive`  — Split

48 check files vs 114 active vs 39 passive. Coverage historically
excluded `checks/`. Same detectors, two trees. Merge checks into
active/passive; delete the extra package.

### 16. Finding specs dump  — Dump

88 tiny files under `analysis/intelligence/findings/specs/`.
They are data, not a module. Move to `src/detection/catalog/` as
declarative specs loaded by the detection registry.

### 17. Reporting platforms / ticketing  — Unwired

`src/reporting/platforms/` has HackerOne, Bugcrowd, Jira-shaped
exporters. GAP: Jira/ServiceNow/DefectDojo not wired to pipeline
output. Treat as `src/reporting/exporters/` with a
`FindingExporter` protocol; pipeline reporting stage is the only caller.

### 18. Swarm / DRL / GNN  — Unwired shells

- `src/intelligence/swarm/` (~193 lines, no LLM/consensus)
- `core/frontier/drl_evasion.py` (HMM only; no PPO)
- GNN unconnected to Kuzu

Do **not** mix these into frontier or intelligence scoring.
If they ship, they are `src/learning/rl` and `src/intel/graph` with
explicit “disabled unless extra extra installed”.

### 19. Decision  — Underdeveloped

7 files: hunt budget, priority queue, attack selection.
Pipeline planner also selects stages. Collapse into
`src/pipeline/decision/` **or** grow `src/decision/` as the only
place the scheduler asks “what next?”. Do not leave both.

### 20. API tester  — Dump

`src/api_tests/apitester` is a product workflow (advanced/detailed/scope)
imported by architecture tests and dashboard. It is not pytest.
Move to `src/workflows/` so `tests/` and `api_tests/` stop meaning
two different things.

---

## Proposed target map

```
src/auth            session kinds, capabilities
src/jobs            job state machine + store
src/notifications   inbox + channels + fetch policy
src/detection       plugin contract + WAF/AST/browser/timing + catalog
src/analysis        active/passive runners only (no registry, no TI)
src/exploitation    engines + payloads
src/execution       sandbox (WASM/AEVE) + validators
src/fuzzing         all mutators (core mutation_engine moves here)
src/frontier        CRDT + WAL
src/checkpoint      snapshot + replay
src/resilience      retry + breaker + Retry-After
src/cache           unified cache
src/realtime        WS rooms + SSE fanout
src/mesh            gossip + bloom
src/intel           feeds + correlation + severity model
src/learning        FP loop only
src/reporting       templates + exporters
src/pipeline        DAG + scheduler (uses the above, owns none of them)
src/dashboard       FastAPI mounts + SPA only
```

Frontend mirrors the nouns under `frontend/src/features/*`.

---

## Extraction order (do not boil the ocean)

1. **Auth session type** — unblocks demo 401s and notification policy
2. **Notifications policy** — one `should_fetch(session)` 
3. **Jobs domain** — dashboard routers become thin
4. **Detection ↛ analysis import** — break the cycle
5. **Resilience merge** — one breaker, persist it
6. **Frontend features/theme + features/jobs** — stop layout/CSS dumps
7. Then frontier/checkpoint/cache/realtime as time allows

Each step: public `__init__` + import-linter contract + tests in
`tests/unit/<module>/`. No “move 400 files” PR.

---

## What this is not

- Not a rewrite.
- Not “add empty packages” (`kernel` / `core_domain` already failed that).
- Not mixing Night City, fuzzing, or WASM into `core` because a test
  needed an import.
