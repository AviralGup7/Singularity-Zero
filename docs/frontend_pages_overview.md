# Frontend Pages Overview

Routes are declared in `frontend/src/RouteConfig.tsx`. Default theme: `mode: 'dark'`, `preset: 'night-city'` (`frontend/src/stores/themeStore.ts`). Telemetry merges REST + SSE + WebSocket through `frontend/src/telemetry/normalizer.ts`.

## Live routes

| Path | Page | Notes |
|---|---|---|
| `/login` | `LoginPage` | Guest/admin depends on `DASHBOARD_AUTH_DISABLED` |
| `/` | `DashboardPage` | KPI shell |
| `/targets` | `TargetsPage` | Scope / assets |
| `/jobs` | `JobsPage` | Job list |
| `/jobs/:id` | `JobDetailPage` | Stage theater + logs |
| `/findings` | `features/findings/FindingsPage` | Triage table |
| `/findings-timeline` | `FindingsTimelinePage` | Rate-limited GET `/api/findings/` |
| `/bug-bounty` | `BugBountyDashboardPage` | Platform drafts |
| `/pipeline` | `PipelineOverviewPage` | DAG view |
| `/settings` | `SettingsPage` | Keys / sinks |
| `/cockpit` | `CockpitPage` | 3D graph |
| `/replay` | `ReplayInterface` | Request replay |
| `/cache-management` | `CacheManagementPage` | Admin role |
| `/risk` | `RiskHubPage` | Risk index |
| `/target-comparison` | `TargetComparison` | Asset diff |
| `/scan-diff` | `ScanDiffPage` | Run diff |
| `/mesh` | `MeshHealthPage` | Gossip / HLC |
| `/security` | `SecurityResiliencePage` | Breakers |
| `/detection-quality` | `DetectionQualityPage` | FP / precision |
| `/tracing` | `TracingPage` | Spans |
| `/audit-logs` | `AuditLogViewer` | HMAC audit |
| `/reports` | `ReportLibraryPage` | Artifacts |
| `/reports/builder` | `ReportBuilderPage` | PDF / SARIF |
| `/evidence-custody/:evidenceId` | `ChainOfCustodyViewer` | Invalid id → `/` |
| `/evasion` | `EvasionMetricsPage` | WAF / HMM |
| `/governance` | `GovernanceHubPage` | Policy gate |
| `/analytics` | `AnalyticsHubPage` | Trends |
| `*` | `NotFoundPage` | |

Pages that exist as modules but are **not** in `RouteConfig` (for example `AcceptancePage`, `LearningPage`, `RemediationPlanner`, `ComplianceDashboard`, `AssetCriticalityPage`, `EvidenceCustodyPage`, `SelfHealingPage`, `RiskScorePage`) are unrouted. Do not document them as operator destinations.

## Real-time endpoints (backend)

| Channel | Path |
|---|---|
| REST job | `GET /api/jobs/{id}` |
| SSE progress | `GET /api/jobs/{id}/progress/stream` |
| Log WebSocket | `/ws/logs/{job_id}` |
| Triage WebSocket | `/ws/triage/{run_id}` |

`useJobMonitor` falls back to REST polling when WS drops. Origin check on the WebSocket handshake runs before the no-security admin grant.

## Job resume

Creating a dashboard job sets `force_fresh: true` by default (`src/dashboard/pipeline_jobs.py`). The UI therefore always passes `--force-fresh-run` unless the job explicitly sets `force_fresh=False`.
