# Frontend Pages & Routes Overview

This document provides a screen-by-screen breakdown of all top-level routes and operational pages in the Cyber Security Test Pipeline frontend.

---

## 🔐 Authentication & Session Views

### `/login` — `LoginPage.tsx`
- **Purpose**: Authenticate operators into the control console.
- **Capabilities**:
  - Role-based authentication (Analyst, Lead, Viewer).
  - API Key token authorization.
  - Development guest token mode.
- **Backend Service**: `src/dashboard/fastapi/routers/security.py` and `src/auth/session.py`.

---

## 📊 Core Operations Views

### `/` — `DashboardPage.tsx`
- **Purpose**: Executive overview of active operations, finding statistics, and system health.
- **Capabilities**: Real-time KPI cards (Active Scans, Critical Vulnerabilities, System Health), recent job list, finding trends, and scan launch shortcuts.
- **Backend Service**: `GET /api/dashboard` and WebSocket telemetry broadcast.

### `/jobs` — `JobsPage.tsx`
- **Purpose**: Scan execution queue and historical job tracking.
- **Capabilities**: Paginated job list, real-time progress indicators, status filtering (Running, Completed, Failed, Queued), and batch actions (Cancel, Restart).
- **Backend Service**: `src/dashboard/fastapi/routers/jobs/`.

### `/jobs/:jobId` — `JobDetailPage/JobDetailPage.tsx`
- **Purpose**: In-depth inspection of a specific scan job execution.
- **Capabilities**:
  - **Stage Theater**: Visual step-by-step DAG execution timeline.
  - **Live Log Terminal**: Real-time stdout/stderr stream with search and log level filters.
  - **Streaming Findings**: Real-time finding table updating as vulnerabilities are discovered.
  - **Artifact Drawer**: Downloadable SARIF reports, raw JSON dumps, and evidence bundles.
- **Backend Service**: `GET /api/jobs/{job_id}`, `/api/jobs/{job_id}/progress/stream` (SSE), `/ws/logs/{job_id}`.

### `/targets` — `TargetsPage.tsx`
- **Purpose**: Attack surface inventory and scope boundary management.
- **Capabilities**: Asset discovery list, wildcards, CIDR blocks, tagging, asset criticality scoring, and bulk scan triggering.
- **Backend Service**: `src/dashboard/fastapi/routers/targets.py`.

### `/findings-timeline` — `FindingsTimelinePage.tsx`
- **Purpose**: Chronological vulnerability discovery and historical trends.
- **Capabilities**: Timeline graph mapping vulnerabilities across scan dates, filtering by severity and target domain.
- **Backend Service**: `src/dashboard/fastapi/routers/findings/`.

---

## 🕹️ Cockpit & Advanced Analytics Views

### `/cockpit` — `CockpitPage.tsx`
- **Purpose**: 3D interactive attack graph and threat correlation cockpit.
- **Capabilities**:
  - GPU-accelerated 3D attack graph rendering (React Three Fiber + Three.js).
  - Node selection displaying CVSS vectors and exploitation evidence.
  - Multi-hop lateral movement visualization.
- **Backend Service**: `GET /api/cockpit/nodes`, `GET /api/cockpit/edges`.

### `/analytics` — `AnalyticsHubPage.tsx` & `/risk-score` — `RiskScorePage.tsx`
- **Purpose**: Risk scoring models and security posture trends.
- **Capabilities**: Composite Severity Index (CSI) distributions, remediation velocity metrics, and vulnerability family heatmaps.
- **Backend Service**: `src/dashboard/fastapi/routers/risk.py` and `src/dashboard/fastapi/routers/compliance.py`.

### `/cache-management` — `CacheManagementPage/CacheManagementPage.tsx`
- **Purpose**: Unified cache and Bloom filter synchronization inspector.
- **Capabilities**: Cache hit/miss rates, LRU memory consumption, Bloom filter saturation gauge, and manual cache purging.
- **Backend Service**: `src/dashboard/fastapi/routers/cache.py` and `src/cache/`.

### `/mesh-health` — `MeshHealthPage.tsx`
- **Purpose**: Distributed node cluster topology and health monitor.
- **Capabilities**: Cluster peer list, SWIM gossip status, leader election state, and shard load balance meters.
- **Backend Service**: `src/dashboard/fastapi/routers/mesh.py`.

### `/settings` — `SettingsPage.tsx`
- **Purpose**: System configuration, notification sinks, and API key management.
- **Capabilities**: Configure Slack/Discord webhooks, edit rate limits, rotate encryption keys, and manage scan profiles.
- **Backend Service**: `src/dashboard/fastapi/routers/defaults.py` and `src/dashboard/fastapi/routers/security.py`.
