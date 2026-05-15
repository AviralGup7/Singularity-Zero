# Frontend Handbook

This document is the current source of truth for the frontend in this repository.

Scope:
- Runtime architecture
- Routes and major pages
- Data flow (REST, SSE, WebSocket, polling)
- State and persistence
- Styling and motion systems
- Testing, build, and troubleshooting
- Extension guidelines for future work

Date context:
- Verified against the current workspace on 2026-04-08.

---

## 1. Tech Stack

Core:
- React `19.2.4`
- TypeScript `6.0.2`
- Vite `8.0.3`
- React Router `7.14.0`
- Axios `1.14.0`

UI and interaction:
- Framer Motion (default animation engine)
- GSAP (heavy cinematic sequences)
- Lottie React (state animations)
- Auto Animate (list diff polish)
- Radix UI primitives
- Lucide icons

Data and charts:
- D3 primitives (`d3-scale`, `d3-shape`, `d3-array`)
- Recharts

Testing:
- Vitest + Testing Library (unit/component)
- Playwright (e2e, audit, visual)
- Storybook

---

## 2. Project Layout

Primary frontend root:
- `D:\cyber security test pipeline - Copy\frontend`

Main source tree:
- `frontend/src/api`: API modules and transport core
- `frontend/src/components`: UI components
- `frontend/src/context`: React context providers
- `frontend/src/hooks`: reusable hooks and real-time monitoring
- `frontend/src/i18n`: translation setup and resources
- `frontend/src/lib`: app-level utilities and contracts
- `frontend/src/pages`: route pages
- `frontend/src/styles`: canonical CSS system
- `frontend/src/tests`: Vitest unit/component tests
- `frontend/tests`: Playwright e2e/audit/visual suites

---

## 3. Runtime Entry and Boot

Entrypoint:
- `frontend/src/main.tsx`

Boot sequence:
1. Imports `frontend/src/styles/index.css` (single style pipeline entry).
2. Registers `vite:preloadError` auto-reload for stale chunk recovery.
3. Lazily imports init helpers from `@/utils/init` if available.
4. Installs global handlers for:
   - uncaught JS errors
   - unhandled promise rejections
   - resource load failures
5. Renders `<App />` under `StrictMode`.

Notable behavior:
- Error overlay rendering is XSS-safe via `textContent`.
- Stack traces are shown only in dev mode.
- Missing `#root` throws explicit overlay.

---

## 4. App Composition and Providers

App wrapper:
- `frontend/src/App.tsx`

Provider order:
1. `I18nextProvider`
2. `LazyMotion` (Framer)
3. `BrowserRouter`
4. `ThemeProvider`
5. `DisplayProvider`
6. `SettingsProvider`
7. `AuthProvider`
8. `LiveAnnouncer`
9. `ToastProvider`

Cross-cutting wrappers:
- `AppLayout` (shell, nav, HUD, footer, command palette)
- `RouteGuard` (auth and permission checks)
- `ErrorBoundary` around each lazy route
- `PageTransition` for route-level motion

---

## 5. Routes and Pages

Defined in `frontend/src/App.tsx`.

Main routes:
- `/` -> Dashboard
- `/login` -> Login
- `/targets` -> Targets
- `/jobs` -> Jobs
- `/jobs/:jobId` -> Job Detail
- `/pipeline` -> Pipeline Overview
- `/findings` -> Findings
- `/gap-analysis` -> Gap Analysis
- `/replay` -> Replay
- `/settings` -> Settings
- `/risk-score` -> Risk Score
- `/findings-timeline` -> Findings Timeline
- `/target-comparison` -> Target Comparison
- `/cache-management` -> Cache Management

Fallback:
- Unknown path redirects to `/`.

---

## 6. Data Layer

### 6.1 API transport

Core transport file:
- `frontend/src/api/core.ts`

Key behavior:
- Axios instance with `VITE_API_BASE` as optional `baseURL`
- Request interceptor:
  - attaches `Authorization` from `sessionStorage.auth_token`
  - adds `X-Request-ID`
  - records timing metadata
- Response interceptor:
  - logs timings in dev
  - caches GET responses
  - normalizes and toasts API errors
  - dispatches `session-expired` event for 401

### 6.2 Cache and retry

Mechanisms:
- `apiCache` for GET TTL cache and stale reads
- retry wrapper `withRetry`
- `cachedGet` and `cachedPost` helpers

Hook-level dedupe:
- `useApi` deduplicates inflight identical requests via a `pendingRequests` map.

### 6.3 API module map

Modules include:
- `jobs.ts`
- `targets.ts`
- `findings.ts`
- `analysis.ts`
- `registry.ts`
- `reports.ts`
- `health.ts`
- `cacheMgmt.ts`
- `replay.ts`
- `export.ts`
- `notes.ts`

Facade:
- `frontend/src/api/client.ts` re-exports most operations used by pages/components.

---

## 7. Real-time Pipeline Tracking

This is the critical path for Jobs and Job Detail.

Primary hook:
- `frontend/src/hooks/useJobMonitor.ts`

Inputs and channels:
1. REST polling
   - `getJob(jobId)` + `getJobLogs(jobId)`
   - poll interval: `2000ms`
2. SSE
   - via `useSSEProgress`
   - endpoint: `/api/jobs/:jobId/progress/stream`
   - event types:
     - `progress_update`
     - `stage_change`
     - `iteration_change`
     - `finding_batch`
     - `completed`
     - `error`
     - `log`
3. WebSocket logs
   - via `useWebSocket`
   - endpoint: `/ws/logs/:jobId`

Merging strategy:
- Stage progress from REST and SSE is merged and normalized.
- Telemetry is merged non-destructively.
- Timeline is normalized against `STAGE_ORDER`.

Failure behavior:
- Explicitly keeps failure metadata:
  - `failed_stage`
  - `failure_reason_code`
  - `failure_step`
  - `failure_reason`
- Keeps `sseError` on terminal `completed` events if payload status is `failed` or `stopped`.

Fallback behavior:
- If streaming degrades, monitor falls back to polling and surfaces warning banner.

---

## ⚠️ Planned Routes (Not Yet Implemented)
The following routes are documented but pending implementation:
- `/risk-score` -> Risk Score page
- `/findings-timeline` -> Findings Timeline view
- `/target-comparison` -> Target Comparison dashboard
- `/cache-management` -> Cache management interface

These will be added in the next sprint.

---

## 8. State Management and Persistence

### 8.1 Contexts

Theme context (`ThemeContext.tsx`):
- `mode`: dark/light
- `accentColor`
- `motionIntensity`: off/low/medium/high
- `effectCapability`: auto/full/reduced/none
- Persists to `localStorage` key `cyber-pipeline-theme`

Display context (`DisplayContext.tsx`):
- density/font-size
- animation and accessibility toggles
- reduced-motion and constrained-device detection
- writes `data-*` attributes on `documentElement`

Settings context (`SettingsContext.tsx`):
- large typed settings tree (dashboard, notifications, pipeline, API, reports, integrations, profiles, logging, rate limiting)
- deep-merge updates by section
- debounced persistence to `localStorage` key `cyber-pipeline-settings`

Auth context (`AuthContext.tsx`):
- role and permission model
- session storage key `cyber-pipeline-auth`
- role gates used by `RouteGuard`

### 8.2 Local state patterns

Patterns used heavily:
- `usePersistedState` for sticky UI filters
- local override maps in Findings UI for responsive updates
- memoized derived state to keep render cost controlled

---

## 9. Styling System

Single entry:
- `frontend/src/styles/index.css`

Canonical import chain:
1. `system/tokens.css`
2. `system/base.css`
3. `system/layout.css`
4. `system/components.css`
5. `system/pages.css`
6. `system/motion.css`

Token strategy:
- Dark-first design tokens with explicit light-mode parity
- CSS variables for:
  - color surfaces and status
  - typography
  - spacing
  - radius
  - shadows
  - motion durations

Responsive shell:
- desktop sidebar + command header
- mobile off-canvas sidebar + bottom dock

Print strategy:
- hides shell/nav/interactive overlays
- preserves core content and tables for printable output

---

## 10. Motion System

Contract file:
- `frontend/src/lib/motionPolicy.ts`

Input factors:
- Theme motion intensity
- Effect capability
- Display animation toggle
- Reduce motion preference
- System `prefers-reduced-motion`
- Constrained device signal

Outputs:
- Policy tier: `static | reduced | full`
- Engine allowances:
  - Framer: not static
  - GSAP: full only
  - Lottie: not static
  - Auto Animate: not static

Component classes:
- `layout`, `page`, `card`, `list`, `status`, `hero`, `graph`

Consumer hook:
- `frontend/src/hooks/useMotionPolicy.ts`

---

## 11. Ops Visual Intelligence Layer

Main components:
- `frontend/src/components/ops/StageTheater.tsx`
- `frontend/src/components/ops/ThroughputStrip.tsx`

Where used:
- Job detail page
- Pipeline overview page

Stage Theater:
- Builds node graph from stage metrics
- Uses D3 scales/links for structure
- Uses Framer for pulse/flow/glitch-like failure effects

Throughput Strip:
- Shows jobs/sec, findings/sec, scan velocity, active task count
- Maintains short velocity history strip
- Animated bar wave indicates live system activity

---

## 12. Major Page Responsibilities

Dashboard:
- Mission-control summary cards
- Hot targets, next actions, trend charts
- Job/target/findings summary blocks
- Inline live terminal feed

Jobs:
- Search/filter by status/mode/failure code
- Triage-focused list with quick restart/stop pathways

Job Detail:
- Unified status header + connection badges
- Persistent recon-failure card and failure diagnostics
- Stage progress bars, stage theater, throughput strip
- Telemetry panel, module stats, logs, timeline

Pipeline Overview:
- Aggregated stage theater across jobs
- Throughput strip and stage heatmaps
- Active job stage cards

Findings:
- Table + kanban modes
- Filtering, sorting, pagination
- Bulk actions, false-positive flow, detail panel

Settings:
- Multi-tab control center for theme/display/pipeline/security/integrations/performance/accessibility/data

---

## 13. Internationalization and Copy

i18n setup:
- `frontend/src/i18n/index.ts`
- active language resources: `frontend/src/i18n/en/translation.json`

Copy guard:
- `frontend/scripts/copy-guard.mjs`
- Prebuild check fails if forbidden exact phrase appears in user-facing TSX/JSX/i18n sources.

Current build pipeline:
- `prebuild` runs `check:copy-guard`

---

## 14. Commands and Workflows

Run locally:
- `npm run dev`

Type check:
- `npm run check:types`

Lint:
- `npm run lint`

Build:
- `npm run build`

Tests:
- `npm test` (Vitest watch)
- `npm run test:run` (Vitest once)
- `npm run test:coverage`
- `npm run test:e2e`
- `npm run test:visual`
- `npm run test:audit`

Health sweep:
- `npm run health`

---

## 15. Testing Structure

Vitest:
- config: `frontend/vitest.config.ts`
- setup: `frontend/src/tests/setup.ts`
- unit tests under `frontend/src/tests/unit`

Playwright:
- config: `frontend/playwright.config.ts`
- e2e specs: `frontend/tests/e2e`
- visual specs: `frontend/tests/visual`
- audit specs: `frontend/tests/audit`

Coverage focus:
- Includes `src/**/*.ts(x)`
- Excludes stories, test utilities, declarations, `main.tsx`

---

## 16. Security and Reliability Notes

Implemented safeguards:
- Global error overlay with escaped text content
- Interceptor-based user-safe error messaging
- Auth token request attachment
- Session-expiry event handling
- Dev server security headers in Vite config
- Route-level guards + permission checks
- Stale chunk reload recovery with `vite:preloadError`

Operational reliability:
- SSE heartbeat timeout and exponential backoff
- SSE fallback to polling mode
- WebSocket reconnect with backoff
- Job monitor merges data from multiple channels to avoid silent stale UI

---

## 17. Environment Variables

Used keys:
- `VITE_API_BASE` (API base URL; empty in dev with Vite proxy)
- `VITE_ENABLE_NOTIFICATION_DIGEST`
- `VITE_NOTIFICATION_DIGEST_MAX_ITEMS`
- `VITE_NOTIFICATION_DIGEST_THROTTLE_MS`

Defined in:
- `frontend/.env`
- `frontend/src/config.ts`

---

## 18. Known Issues and Current Constraints

1. Locked legacy folder on disk:
- `frontend/src/styles/cyberpunk/*`
- Not imported by current style pipeline.
- Removal currently blocked by OS permission (`EPERM` / access denied) in this environment.

2. Visual text encoding artifacts:
- A few UI strings include mojibake characters in source output capture.
- Functional impact is low, but cleanup is recommended for polish.

3. Large vendor chunk warning:
- `react-vendor` chunk is large.
- Build passes, but further code-splitting can reduce initial payload.

---

## 19. Frontend Extension Guidelines

When adding features:
1. Prefer existing API modules under `src/api` over inline fetch calls.
2. Keep route-level pages thin and move reusable logic to hooks/components.
3. Use `useMotionPolicy` for new animated surfaces.
4. Use tokens and existing CSS utility classes before adding new style branches.
5. Keep failure context explicit in all job-progress flows.
6. Add or update tests:
   - unit for hooks/components
   - visual/e2e for critical user journeys
7. Run at least:
   - `npm run check:types`
   - `npm run build`
   - target test command for the touched area

---

## 20. High-value File Index

Bootstrap and shell:
- `frontend/src/main.tsx`
- `frontend/src/App.tsx`
- `frontend/src/components/layout/AppLayout.tsx`

Real-time pipeline:
- `frontend/src/hooks/useJobMonitor.ts`
- `frontend/src/hooks/useSSEProgress.ts`
- `frontend/src/hooks/useWebSocket.ts`

Data layer:
- `frontend/src/api/core.ts`
- `frontend/src/api/client.ts`
- `frontend/src/hooks/useApi.ts`

Ops visuals:
- `frontend/src/components/ops/StageTheater.tsx`
- `frontend/src/components/ops/ThroughputStrip.tsx`

Style and motion:
- `frontend/src/styles/index.css`
- `frontend/src/styles/system/tokens.css`
- `frontend/src/lib/motionPolicy.ts`

Core pages:
- `frontend/src/pages/DashboardPage.tsx`
- `frontend/src/pages/JobsPage.tsx`
- `frontend/src/pages/JobDetailPage.tsx`
- `frontend/src/pages/PipelineOverviewPage.tsx`
- `frontend/src/pages/findings/FindingsPage.tsx`
- `frontend/src/pages/SettingsPage.tsx`

---

If you want, next I can also generate:
- `frontend-architecture-diagram.md` with Mermaid flow diagrams
- `frontend-api-endpoints.md` as a strict endpoint contract sheet
- `frontend-oncall-runbook.md` focused only on prod incident triage
