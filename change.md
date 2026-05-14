# Codebase Audit: Problems, Fixes & Improvements

> **Generated**: 2026-05-12 | **Scope**: Full codebase scan | **Target**: 200+ items
> **Last Updated**: 2026-05-12 14:10 IST — Removed fixed items, added new findings from re-scan

---

## A. Remaining Pending Issues (from original scan)

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## B. NEW — Bugs Found in Fixed Files (Post-Fix Re-scan)

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## C. NEW — WebSocket & Dashboard Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## D. NEW — Bloom Filter & State Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|
| 230 | `src/core/frontier/bloom.py:81` | Per-item Python loop for `mmh3.hash64()` — O(n) interpreter overhead. | Batch with numpy vectorized operations or C-level bulk API. |

## E. NEW — Ring Bus & Events Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## F. NEW — Remaining Architecture, Docker & Config Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## G. NEW — JWT & Authentication Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## H. NEW — Rate Limiter Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## I. NEW — Job Queue Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## J. NEW — Audit Logger Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|
| 300 | `src/infrastructure/security/audit.py:518-519` | `get_entries` reads the entire file from start for every query. No index, no caching. O(n) per request. | Add in-memory index or SQLite backing store for queries. |

## K. NEW — WebSocket Reconnect & Manager Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## L. NEW — Miscellaneous Cross-Cutting Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|
| 313 | `src/core/frontier/chameleon.py` | No unit tests for `RequestChameleon` — WAF evasion logic is untested. | Add tests for header mutation and UA rotation. |
| 314 | `src/core/frontier/ghost_vfs.py` | No unit tests for `GhostVFS` — encryption/decryption untested. | Add tests for write/read/list/destroy lifecycle. |
| 315 | `src/core/frontier/wasm.py` | No unit tests for `WasmPluginRunner` — memory allocation/deallocation untested. | Add tests with a mock WASM module. |
| 316 | `src/core/frontier/ring_bus.py` | No unit tests for `FrontierRingBus` — event dispatch untested. | Add tests for subscribe/emit/dispatch. |
| 317 | `src/core/frontier/wal.py` | No unit tests for `FrontierWAL` — WAL replay untested. | Add tests with mock Redis. |
| 318 | `src/core/frontier/proc_pool.py` | No unit tests for `FrontierProcessPool` — process lifecycle untested. | Add tests with `echo` or `cat` as tool. |
| 319 | `src/core/frontier/marshaller.py` | No unit tests for `MeshMarshaller` — serialization roundtrip untested. | Add pack/unpack roundtrip tests. |

## M. NEW — Heartbeat, Broadcaster & Protocol Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## N. NEW — Deep Cross-Cutting & Integration Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|

## O. NEW — Frontend State, Virtualization & Overhaul Issues

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|
| 401 | `frontend/src/` | State flicker due to inconsistent timestamp generation and data source conflict (REST, WS, SSE). | Implement Action Buffer queue, unified `useReducer`, and serverTimeOffset correction. |
| 402 | `frontend/src/` | Browser freeze when rendering 100k+ log lines or 5k+ findings in DOM. | Virtualize log viewer and findings grid (e.g., `react-virtuoso`); move parsing to Web Worker. |
| 403 | `frontend/src/` | 3D Cockpit performance degrades exponentially beyond 500 nodes. | Refactor to `THREE.InstancedMesh`; offload node layout to GPGPU or a worker. |
| 404 | `frontend/src/` | Network interruptions result in empty states/silent loading spinners. | Add centralized Toast Hub, jittered exponential backoff for reconnects, and Zod contract guards. |
| 405 | `frontend/src/` | Legacy theming logic and hardcoded colors (`#00ff41`, `#0a0a0a`). | Migrate to unified TailwindCSS design tokens; ensure full keyboard accessibility. |

## P. NEW — Frontend Implementation Gaps & Technical Debt

| # | File | Problem | Fix / Improvement |
|---|------|---------|-------------------|
| 406 | `frontend/src/pages/` | Planned routes are documented but missing complete implementations (`/risk-score`, `/findings-timeline`, `/target-comparison`, `/cache-management`). | Implement missing pages per the sprint plan. |
| 407 | `frontend/src/styles/cyberpunk/*` | Legacy locked folder causing build/cleanup friction (OS permission `EPERM`). | Force-remove the folder via script or configure Vite/build tools to exclude it completely. |
| 408 | `frontend/dist/` (Build) | Large vendor chunk warning for `react-vendor` during Vite build. | Optimize code-splitting and lazily load heavy dependencies (e.g., Three.js, D3). |
| 409 | `frontend/src/` | Visual text encoding artifacts (mojibake characters) in UI strings. | Sanitize source files and ensure UTF-8 encoding across the pipeline. |
| 410 | `frontend/src/utils/storage.ts` | Silently catches and warns on `localStorage`/`sessionStorage` failures (e.g. quota exceeded) without UX fallback. | Add graceful UX degradation and in-memory fallback for storage failures. |

---

**Summary**: 19 items remaining in audit log.

