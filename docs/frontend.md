# Frontend Handbook & Architecture

This document serves as the comprehensive architectural guide and component reference for the React 19 operator console of the Cyber Security Test Pipeline.

---

## 1. Frontend Tech Stack

- **Core Framework**: React `19.2.4` + TypeScript `6.0.2` + Vite `8.0.3`
- **Routing**: React Router `7.18.1` with lazy-loaded route boundaries and transition guards
- **Styling**: Tailwind CSS 4 with unified dark-mode cyberpunk design tokens (`frontend/src/styles/`)
- **State Management**: Zustand global stores (`frontend/src/stores/`) and React Context providers (`frontend/src/context/`)
- **Real-Time Telemetry**: Server-Sent Events (`SSE`), WebSocket log streaming, normalized client state (`frontend/src/telemetry/normalizer.ts`), and REST fallback polling
- **Data Visualization**: React Three Fiber + Three.js (`AttackChainGraph3D.tsx` and 3D Cockpit), Recharts, and D3 primitives
- **Virtualization**: `react-virtuoso` for smooth 60 FPS rendering of 100,000+ log lines and findings
- **Testing**: Vitest, React Testing Library, and Playwright e2e suites

---

## 2. Source Tree Layout (`frontend/src/`)

```text
frontend/src/
├── api/                  # Typed REST API client modules and transport core
│   ├── client.ts         # Central client facade re-exporting API operations
│   ├── contract.ts       # Typed API schema contract interfaces
│   ├── core.ts           # Axios instance with interceptors and CSRF/token injection
│   ├── jobs.ts           # Job lifecycle, trigger, pause, resume, cancel endpoints
│   ├── findings.ts       # Finding queries, triage updates, bulk actions, notes
│   ├── targets.ts        # Target asset management and scope definitions
│   ├── mesh.ts           # Distributed mesh nodes, health, and HLC clock status
│   └── analytics.ts      # Longitudinal vulnerability trends and risk heatmaps
│
├── components/           # Component library organized by domain:
│   ├── charts/           # D3, Recharts, and 3D AttackChainGraph3D widgets
│   ├── cockpit/          # 3D interactive threat graph and HUD overlays
│   ├── common/           # Generic buttons, badges, modals, inputs, tooltips
│   ├── gap-analysis/     # Gap analysis and vulnerability coverage viewers
│   ├── jobs/             # Job cards, execution progress bars, log viewers
│   ├── layout/           # App shell, navigation sidebar, header, breadcrumbs
│   ├── motion/           # Motion transition and animation wrappers
│   ├── ops/              # Stage theater, execution timelines, telemetry gauges
│   ├── report/           # Report builder and compliance attestation cards
│   ├── scope/            # Scope editor and asset tagging modals
│   ├── settings/         # System configuration panels and API key forms
│   ├── targets/          # Target table, asset filters, and import dialogs
│   ├── ui/               # Custom atomic UI controls and layout components
│   └── ui-shadcn/        # Radix UI accessible headless primitives
│
├── context/              # Context providers (Auth, Theme, Sound, Keybindings)
├── hooks/                # Custom React hooks (useJobMonitor, useJobMonitorSse, useWebSocket)
├── pages/                # Top-level route pages (Dashboard, Jobs, Findings, Cockpit, etc.)
├── stores/               # Zustand state stores (jobStore, authStore, displayStore, scopeStore, themeStore)
├── styles/               # Global CSS, theme definitions, and Tailwind 4 directives
├── telemetry/            # Telemetry normalization pipeline (normalizer.ts)
├── types/                # Shared TypeScript contracts and schema interfaces
└── workers/              # Off-thread Web Workers (layout.worker.ts for D3 graph force layout)
```

---

## 3. Real-Time Telemetry & Monitoring Architecture

The operator dashboard maintains high-fidelity real-time synchronization through a tiered telemetry protocol:

```text
┌─────────────────────────────────────────────────────────────┐
│                    useJobMonitor Hook                       │
│  (frontend/src/hooks/useJobMonitor.ts)                      │
└──────────────┬──────────────────┬──────────────────┬────────┘
               │                  │                  │
      REST Polling (2s)        SSE Stream                         WebSocket
      /api/jobs/:id            /api/jobs/:id/progress/stream      /ws/logs/:id
                                                                  /ws/triage/:run_id
               │                  │                  │
               ▼                  ▼                  ▼
     ┌────────────────────────────────────────────────────────┐
     │             Telemetry State Normalizer                 │
     │      (frontend/src/telemetry/normalizer.ts)            │
     │  - Merges stage progress across channels               │
     │  - Normalizes failure codes and stage timeline         │
     │  - Automatically falls back to polling on WS drop      │
     └────────────────────────────────────────────────────────┘
```

---

## 4. Global State Stores (Zustand)

Global UI state is cleanly partitioned across dedicated Zustand stores:
- **`useJobStore`** (`stores/jobStore.ts`): Active job executions, selected job metadata, live stage transitions, finding buffers, and log streams.
- **`useAuthStore`** (`stores/authStore.ts`): JWT session tokens, user roles, authentication status, and CSRF token state.
- **`useDisplayStore`** (`stores/displayStore.ts`): Viewport layout, collapsed panels, active tabs, and filter configurations.
- **`useScopeStore`** (`stores/scopeStore.ts`): Target scope definitions, inclusion/exclusion rules, and verification states.
- **`useThemeStore`** (`stores/themeStore.ts`): Cyberpunk dark/light themes and sound effect preferences.
- **`useEventLogStore`** (`stores/eventLogStore.ts`): Centralized event journal and real-time audit notifications.

---

Routed pages are listed in [frontend_pages_overview.md](frontend_pages_overview.md) (`frontend/src/RouteConfig.tsx`). Findings timeline GETs are prefix-limited (`/api/findings/` 60/min with security, 180/min without).

## 5. 3D Threat Visualization Cockpit

The Cockpit view (`frontend/src/pages/CockpitPage.tsx`, `frontend/src/components/cockpit/`, and `frontend/src/components/charts/AttackChainGraph3D.tsx`) uses Three.js instanced rendering via `@react-three/fiber`:
- **50,000+ Graph Nodes**: Single draw call GPU-instanced rendering of targets, endpoints, and exploit chains.
- **Dynamic Threat Coloring**: Nodes dynamically pulsate based on CVSS severity (Critical = Crimson, High = Orange, Medium = Yellow, Low = Cyan).
- **Interactive Inspection**: Raycasting enables instant node selection, displaying finding evidence and attack graph paths in the HUD drawer.
