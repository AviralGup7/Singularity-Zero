# Architecture Overview

This document is a **non-marketing** map of the codebase.  It describes
the standard engineering patterns we use and the modules that implement
them.  For the branded, capability-focused description, see
`architecture.md`.

---

## High-level shape

```
┌───────────────┐    HTTP / WebSocket    ┌─────────────────────┐
│  React UI     │ ◀─────────────────────▶│  FastAPI dashboard  │
│  (frontend/)  │                        │  (src/dashboard/    │
└───────────────┘                        │   fastapi/)         │
                                        └──────────┬──────────┘
                                                   │ enqueue / status
                                                   ▼
        ┌──────────────────────────────────────────────────┐
        │  Pipeline orchestrator  (src/pipeline/)         │
        │   ├── DAG engine                                │
        │   ├── Stages: recon → active → enrich → report  │
        │   └── Self-healing controller                   │
        └────────┬─────────────────────┬──────────────────┘
                 │                     │
        ┌────────▼────────┐   ┌────────▼────────┐
        │  Recon / scan   │   │  State stores   │
        │  workers        │   │  (Redis / SQLite│
        │  (asyncio +     │   │   + Bloom mesh) │
        │   threadpool)   │   │                 │
        └────────┬────────┘   └─────────────────┘
                 │
        ┌────────▼────────┐
        │  Analysis       │
        │  (active +      │
        │   passive +     │
        │   exploit)      │
        └────────┬────────┘
                 │
        ┌────────▼────────┐
        │  Reporting      │
        │  (HTML / JSON / │
        │   compliance)   │
        └─────────────────┘
```

## Subsystems and the standard patterns they implement

| Subsystem | Location | What it actually is |
|---|---|---|
| Recon collectors | `src/recon/`, `src/recon/collectors/` | Async / threaded URL discovery from archives (Wayback, CommonCrawl), passive DNS, and external services (VirusTotal, URLScan, OTX). |
| Active analysis | `src/analysis/active/` | HTTP request mutation + response inspection to find SQLi, XSS, IDOR, JWT, SSRF, … |
| Passive analysis | `src/analysis/passive/` | Static detectors that read existing responses / JS / spec files for known-bad fingerprints. |
| Execution / exploitation | `src/execution/`, `src/exploitation/` | Validates candidate findings end-to-end.  All exploit PoCs run inside a WASM sandbox (`wasmtime`). |
| Detection registry | `src/detection/`, `src/core/plugins/` | Plugin-based module loader with hot-reload support. |
| Pipeline orchestrator | `src/pipeline/services/pipeline_orchestrator/` | DAG of stages with retry, circuit-breaker, and resume support. |
| Frontier state | `src/core/frontier/` | LWW-set CRDTs keyed by Hybrid Logical Clocks (HLCs).  HLCs were chosen over vector clocks because they give causal ordering in **O(1) space per node** rather than O(N). |
| Mesh coordination | `src/infrastructure/mesh/` | Authenticated SWIM-style gossip for cluster membership and sharding.  Bullies algorithm picks shard leaders. |
| Bloom filter plane | `src/core/frontier/bloom_mesh.py` | Redis pub/sub channel `cyber-pipeline:bloom:sync` ships packed Bloom snapshots between nodes; vector clocks reject stale snapshots and compatible filters merge via packed-bit OR. |
| WebSocket server | `src/websocket_server/` | Per-job broadcast rooms, backpressure buffering, and a heartbeat. |
| Dashboard API | `src/dashboard/fastapi/` | FastAPI app with rate limiting, RBAC, CSRF, and an OpenAPI surface. |
| Reporting | `src/reporting/` | Jinja2 templates assembled into multi-page HTML reports with embedded charts. |
| ML severity | `src/intelligence/ml/`, `src/learning/` | XGBoost + scikit-learn classifier with a pure-NumPy fallback.  Closed-loop retraining on analyst triage signals. |
| Cryptographic secrets | `src/infrastructure/security/`, `src/core/security/` | Argon2-hashed API keys, JWT auth, and a `sensitive_names` allow-list that the entire stack imports. |

## Key invariants

1. **Single source of truth for connection defaults.**
   * Redis timeouts/retries live in `src/infrastructure/queue/redis_config.py`.
   * SQLite timeouts/retries live in `src/infrastructure/db/sqlite_utils.py`.
   * Sensitive parameter / header / body-field names live in
     `src/core/security/sensitive_names.py`.
   * Domain validation regex lives in `src/recon/domain_validation.py`.
   * IP validation lives in `src/core/utils/ip_validation.py`.

   If you find yourself redefining one of these in a new module, that
   is a bug — add the new case to the central module instead.

2. **CRDT mutations go through `NeuralState`.**  Direct writes to the
   frontier state are not supported; everything funnels through the
   `LWWset` API so the HLC ordering is preserved.

3. **All credential inputs are validated centrally.**  Any function
   that accepts a domain, URL, IP, or query string must go through
   the helpers above.  Ad-hoc regexes are forbidden by code review.

4. **The pipeline orchestrator owns the lifecycle.**  Stages are
   stateless w.r.t. the rest of the system; everything that needs
   to survive a restart is persisted via `output_store.py` or the
   Redis WAL in `src/core/frontier/wal.py`.

5. **The Python actor layer still uses `pykka`.**  Earlier docs
   described a "Pykka replacement" that was never fully landed; the
   code still subclasses `pykka.ThreadingActor` for the thread-based
   actor pool.  Don't add new Pykka-specific abstractions; new code
   should use plain `asyncio` workers.

## Threat model (short form)

* **In scope**: the platform is treated as trusted.  Inputs from the
  operator (CLI flags, YAML config, API keys) are trusted.  Target
  traffic is **untrusted** and probed defensively.
* **Out of scope**: We do not protect against an attacker who has
  shell access on the operator's machine.  Secrets stored in `.env`
  are trusted.
* **Sandboxing**: Untrusted PoC code (exploiters) runs in a
  `wasmtime` sandbox; Python plugins run in a separate process and
  are AST-validated before execution.

## Where to read next

* `architecture.md` — branded, capability-focused walkthrough.
* `docs/FAILURE_MODES.md` — how to distinguish a clean run from a
  degraded one.
* `docs/environment-variables.md` — every env var the system reads.
* `CONTRIBUTING.md` — workflow and code style.

