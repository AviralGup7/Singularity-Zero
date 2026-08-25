# Frontend Handbook & Architecture

This document serves as the comprehensive architectural guide and component reference for the React 19 operator console of the Cyber Security Test Pipeline.

---

## 1. Frontend Tech Stack

- **Core Framework**: React `19.2.4` + TypeScript `6.0.2` + Vite `8.0.3`
- **Routing**: React Router `7.14.0` with lazy-loaded route boundaries and transition guards
- **Styling**: Tailwind CSS 4 with unified dark-mode cyberpunk design tokens (`frontend/src/styles/`)
- **State Management**: Zustand global stores (`frontend/src/stores/`) and React Context providers (`frontend/src/context/`)
- **Real-Time Telemetry**: Server-Sent Events (`SSE`), WebSocket log streaming, and REST fallback polling
- **Data Visualization**: React Three Fiber + Three.js (3D Attack Graph Cockpit), Recharts, and D3 primitives
- **Virtualization**: `react-virtuoso` for smooth 60 FPS rendering of 100,000+ log lines and findings
- **Testing**: Vitest, React Testing Library, and Playwright e2e suites

---

## 2. Source Tree Layout (`frontend/src/`)

```text
frontend/src/
├── api/                  # Typed REST API client modules and transport core
│   ├── client.ts         # Central client facade re-exporting API operations
│   ├── core.ts           # Axios instance with request/response interceptors and token injection
│   ├── jobs.ts           # Job lifecycle, trigger, pause, resume, cancel endpoints
│   ├── findings.ts       # Finding queries, triage updates, bulk actions, notes
│   ├── targets.ts        # Target asset management and scope definitions
│   ├── mesh.ts           # Distributed mesh nodes, health, and HLC clock status
│   └── analytics.ts      # Longitudinal vulnerability trends and risk heatmaps
│
├── components/           # Component library organized by domain:
│   ├── charts/           # Reusable D3 and Recharts visualization widgets
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
│   └── ui/               # Radix UI accessible headless primitives
│
├── context/              # Context providers (Auth, Theme, Sound, Keybindings)
├── hooks/                # Custom React hooks (useJobMonitor, useSSEProgress, useWebSocket)
├── pages/                # Top-level route pages (Dashboard, Jobs, Findings, Cockpit, etc.)
├── stores/               # Zustand state stores (useJobStore, useFindingsStore, useMeshStore)
├── styles/               # Global CSS, theme definitions, and Tailwind 4 directives
└── types/                # Shared TypeScript contracts and schema interfaces
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
      REST Polling (2s)        SSE Stream        WebSocket Stream
      /api/jobs/:id            /progress/stream   /ws/logs/:id
               │                  │                  │
               ▼                  ▼                  ▼
     ┌────────────────────────────────────────────────────────┐
     │             Telemetry State Normalizer                 │
     │  - Merges stage progress across channels               │
     │  - Normalizes failure codes and stage timeline         │
     │  - Automatically falls back to polling on WS drop      │
     └────────────────────────────────────────────────────────┘
```

---

## 4. Global State Stores (Zustand)

Global UI state is cleanly partitioned across dedicated Zustand stores:
- **`useJobStore`**: Active job executions, selected job metadata, live stage transitions, and log buffers.
- **`useFindingsStore`**: Paginated finding lists, active severity filters, triage status changes, and offline queue actions.
- **`useMeshStore`**: Cluster peer node topology, leader node status, Bloom filter synchronization states, and region health.

---

## 5. 3D Threat Visualization Cockpit

The Cockpit view (`frontend/src/pages/CockpitPage.tsx` and `frontend/src/components/cockpit/`) uses Three.js instanced rendering via `@react-three/fiber`:
- **50,000+ Graph Nodes**: Single draw call GPU-instanced rendering of targets, endpoints, and exploit chains.
- **Dynamic Threat Coloring**: Nodes dynamically pulsate based on CVSS severity (Critical = Crimson, High = Orange, Medium = Yellow, Low = Cyan).
- **Interactive Inspection**: Raycasting enables instant node selection, displaying finding evidence and attack graph paths in the HUD drawer.
