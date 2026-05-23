# Singularity-Zero — Changelog

All changes, improvements, dependency updates, bug fixes, and refactors across the full codebase. Similar or near-identical changes are counted as one entry. Ordered by subsystem.

---

## Infrastructure & CI/CD

1. Migrated full project to Replit environment with working dev/backend workflows
2. Created `start_backend.py` entry point for uvicorn on port 8080
3. Configured "Start application" workflow (Vite dev server, port 5000)
4. Configured "Start backend" workflow (uvicorn, port 8080)
5. Fixed CI pipeline — replaced broken `semgrep/scanning-action@v4` with pip-install approach
6. Added `beartype>=0.18.0` to `pyproject.toml` dev dependencies for runtime type checking
7. Removed unused `Target` and `Job` imports from `frontend/src/api/client.ts` that broke ESLint
8. Created `.github/workflows/auto-push-fixes.yml` — auto-runs `ruff --fix` + `eslint --fix` on CI failure and commits as Aviral Gupta
9. Upgraded `docker/metadata-action` v5 → v6 in `publish.yml` (both build stages)
10. Upgraded `docker/metadata-action` v5 → v6 in `release.yml`
11. Upgraded `docker/setup-buildx-action` v3 → v4 in `publish.yml` (both build stages)
12. Upgraded `docker/setup-buildx-action` v3 → v4 in `release.yml`
13. Upgraded `docker/login-action` v3 → v4 in `publish.yml` (both build stages)
14. Upgraded `docker/login-action` v3 → v4 in `release.yml`
15. Upgraded `mikepenz/release-changelog-builder-action` v5 → v6 in `release.yml`
16. Upgraded `softprops/action-gh-release` v2 → v3 in `release.yml`
17. Upgraded base Docker image from `python:3.13-slim-bookworm` → `python:3.14-slim-bookworm` (both builder and runtime stages)
18. Merged and deleted all 17 outstanding Dependabot branches — repo now has only `main`
19. All Dependabot dependency updates integrated manually into `main` in a single clean commit set
20. Git history cleaned: no diverged dependabot branches remain
21. Docker multi-arch build targets `linux/amd64` and `linux/arm64`
22. GitHub Actions uses GHA cache (`type=gha`) for Docker layer caching across all workflows
23. `publish.yml` conditionally builds optimized Docker image only when `Dockerfile.optimized` exists
24. Release workflow generates structured changelog via `release-changelog-builder-action` with categorized labels
25. CI runs `ruff check` + `ruff format --check` as lint gates
26. CI runs `pytest tests/unit -v --tb=short` as test gate
27. `pyproject.toml` requires Python `>=3.14`
28. All workflows set `git config user.name/email` to "Aviral Gupta" before any commit step
29. `docker-compose.yml` and `docker-compose.optimized.yml` provided for local multi-service dev
30. Prometheus datasource and dashboard configs provisioned under `configs/grafana/`

---

## Python Dependencies

31. Upgraded `rich` upper bound from `<15.0.0` → `<16.0.0`
32. `httpx>=0.28.0,<1.0.0` — async HTTP client for all backend requests
33. `aiohttp>=3.13.0,<4.0.0` — secondary async HTTP layer for high-concurrency scans
34. `pydantic>=2.12.0,<3.0.0` + `pydantic-settings>=2.13.0,<3.0.0` for settings and model validation
35. `fastapi>=0.115.0,<1.0.0` + `uvicorn[standard]>=0.30.0` for dashboard API server
36. `loguru>=0.7.3` for structured logging throughout all modules
37. `cryptography>=46.0.6,<50.0.0` for TLS/cert operations in scanning modules
38. `dnspython>=2.8.0` for DNS enumeration and subdomain validation
39. `beautifulsoup4>=4.14.0,<5.0.0` for HTML parsing in recon and JS discovery
40. `jinja2>=3.1.6,<4.0.0` for HTML report templating
41. `click>=8.3.0,<9.0.0` for CLI entry points
42. `beartype>=0.18.0` added as dev dependency for zero-overhead runtime type validation

---

## Python Backend — Import & Type Fixes

43. Added `from typing import Any` to `src/websocket_server/manager.py` (was causing `NameError`)
44. Added `from typing import Any` to `src/websocket_server/heartbeat.py`
45. Added `from typing import Any` to `src/websocket_server/_main.py`
46. Added `from __future__ import annotations` to websocket server modules for forward-reference compatibility
47. Fixed missing type annotations across analysis active modules to satisfy `beartype`
48. Resolved circular import between `pipeline.services` and `dashboard` modules
49. Replaced `Optional[X]` with `X | None` syntax across Python 3.14-compatible modules
50. Removed stale `TYPE_CHECKING` guards that were hiding real import errors

---

## Python Backend — WebSocket Server

51. `manager.py` — WebSocket connection manager with per-job broadcast rooms
52. `heartbeat.py` — periodic ping/pong keepalive with configurable interval
53. `broadcaster.py` — fan-out broadcast to all subscribers for a given job ID
54. `handlers.py` — message dispatch router for inbound WebSocket frames
55. `protocol.py` — typed message envelope (type, payload, timestamp)
56. `reconnect.py` — exponential-backoff reconnect logic for dropped connections
57. `auth.py` — WebSocket handshake token validation
58. `integration.py` — hooks WebSocket server into FastAPI lifespan events

---

## Python Backend — Dashboard / FastAPI API

59. FastAPI app mounted with CORS, lifespan startup/shutdown, and WebSocket integration
60. `/api/health/live` and `/api/health/ready` endpoints returning structured status
61. Job CRUD endpoints: create, list, get, cancel via `pipeline_jobs.py`
62. `job_store.py` — in-memory + optional persistent job state store with TTL eviction
63. `job_state.py` — typed job state machine (pending → running → complete/failed)
64. `rate_limiter.py` — per-IP token-bucket rate limiting on all API routes
65. `registry/` — plugin/module registry with capability introspection endpoint
66. `controls/` — runtime pipeline controls (pause, resume, abort exposed via REST)
67. `runtime_controls.py` — exposes live pipeline control signals over the API
68. `remediation.py` — remediation suggestion lookup by finding type
69. `eta_engine.py` — duration forecasting based on target complexity heuristics
70. `launcher_forensics.py` — records launcher metadata (version, flags, env) per job
71. `dashboard_cli.py` — CLI wrapper to start the dashboard with custom config
72. `configuration.py` — pydantic-based settings loaded from env/YAML
73. `constants/` — shared string constants to avoid magic literals across dashboard
74. `services/` — shared service singletons (job store, notification bus) injected via DI

---

## Python Backend — Pipeline & Orchestration

75. DAG engine (`dag_engine.py`) — directed acyclic graph execution of pipeline stages with topological sort
76. `orchestrator.py` — main pipeline orchestrator coordinating all stages
77. `parallel.py` — concurrent stage execution for independent DAG nodes
78. `_stage_retry.py` — per-stage retry with configurable backoff and jitter
79. `_run_execution.py` — single-run execution wrapper with timeout enforcement
80. `learning_hooks.py` — post-run hooks that feed outcomes into the learning module
81. `_orchestrator_helpers.py` + `_helpers.py` — shared orchestration utility functions
82. `_constants.py` — pipeline stage names and timeout defaults
83. `_state_helpers.py` — job state mutation helpers used across orchestrator
84. Stage: `recon.py` — orchestrates full reconnaissance phase
85. Stage: `active_scan.py` + `_active_scan_adaptive.py` — adaptive active scanning with workload balancing
86. Stage: `access_control.py` — RBAC/BFLA/IDOR checks as dedicated pipeline stage
87. Stage: `analysis.py` — post-scan static and dynamic analysis aggregation
88. Stage: `enrichment.py` — CVE lookup, threat intel enrichment per finding
89. Stage: `nuclei.py` — Nuclei template runner stage with schema validation
90. Stage: `semgrep.py` — static analysis stage via Semgrep with pip-installed runner
91. Stage: `validation.py` — finding deduplication and confidence scoring stage
92. Stage: `reporting.py` — report generation stage (HTML + JSON)
93. `_recon_network/` — sub-orchestration for live-host probing and URL collection
94. `live_hosts_orchestrator.py` — async parallel probing of discovered hosts
95. `url_collection_orchestrator.py` — multi-source URL aggregation with dedup
96. `url_stats.py` — per-collection statistics (count, response codes, size distribution)
97. `checkpoint_persistence.py` — serialises and restores pipeline state across restarts
98. `circuit_breaker.py` — per-stage circuit breaker to stop cascading failures
99. `job_artifact_packager.py` — bundles scan artifacts (logs, screenshots, reports) into zip
100. `notification_service.py` — routes job events to WebSocket broadcast and email/webhook sinks
101. `output_store.py` — content-addressable storage for raw scan output blobs
102. `pipeline_flow.py` — high-level flow control (start, pause, resume, abort)
103. `pipeline_helpers.py` — shared helper functions used across pipeline services
104. `plugin_catalog.py` — discovers and validates installed scan plugins at startup
105. `sandbox.py` — subprocess sandboxing for running external tools with resource limits
106. `tool_execution.py` — tool invocation wrapper with timeout, stdout capture, exit-code checking
107. `runner.py` + `runner_support.py` — top-level job runner tying orchestrator to job store
108. `runtime.py` — runtime environment detection (available tools, OS, Python version)
109. `cache.py` + `cache_backend.py` — two-tier result cache (memory + disk) with LRU eviction
110. `parallel_analysis.py` — fan-out analysis tasks across asyncio workers
111. `retry.py` — generic retry decorator with exponential backoff used across pipeline
112. `maintenance.py` — periodic cleanup of expired jobs, artifacts, and cache entries
113. `screenshot_diff.py` + `screenshots.py` — before/after screenshot capture and pixel-diff for visual regression
114. `storage.py` — job-scoped file storage abstraction (local or object-store backed)
115. `tools.py` + `tools_capabilities.py` — tool discovery, capability flags, and version negotiation
116. `validation.py` — pipeline input validation (URL format, auth headers, scan config)
117. `analyst_notes.py` — persistent analyst notes attached to job runs

---

## Python Backend — Security Analysis Modules

118. `active/coordinator.py` — dispatches active checks to all registered attack modules
119. `active/http_methods.py` — tests dangerous HTTP verbs (TRACE, DELETE, PUT, PATCH)
120. `active/http_smuggling.py` — CL.TE and TE.CL HTTP request smuggling probes
121. `active/cloud_metadata.py` + `cloud_constants.py` — SSRF probes targeting cloud metadata endpoints (AWS, GCP, Azure)
122. `active/graphql.py` — GraphQL introspection abuse, batching attacks, field suggestion leakage
123. **Injection suite** (grouped — 14 attack types, each a dedicated module):
     `xss_reflect_probe.py`, `dom_xss.py`, `ssrf.py`, `proxy_ssrf.py`, `grafana_ssrf.py`,
     `command_injection.py`, `ldap.py`, `xpath.py`, `nosql.py`, `xxe.py`, `xxe_detection.py`,
     `ssti.py`, `deserialization.py`, `open_redirect.py`
124. `injection/crlf/` — CRLF injection with path variants, URL variants, WAF detection, heuristic scoring, and response validation (7 sub-modules)
125. `injection/host_header.py` — Host header injection and cache-poisoning probes
126. `injection/csrf.py` — CSRF token absence and weak-token checks
127. `injection/jwt_manipulation.py` — JWT tampering within injection context
128. `injection/method_tampering.py` — HTTP method override via headers (`X-HTTP-Method-Override`)
129. `injection/parameter_pollution.py` — HTTP parameter pollution (HPP) attack probes
130. `injection/path_traversal.py` — directory traversal with platform-specific payloads
131. `injection/oauth_testing.py` — OAuth2 flow abuse (redirect URI, state param, PKCE bypass)
132. `injection/websocket_hijacking.py` — WebSocket hijacking and protocol confusion checks
133. `injection/_patterns.py` — shared regex patterns for detection across injection types
134. `injection/_payload_generator.py` — context-aware payload generation by parameter type
135. `injection/_waf_detector.py` + `injection/_confidence.py` — WAF fingerprinting and confidence scoring
136. `injection/_context_detector.py` + `injection/_efficiency.py` — context inference and probe efficiency scoring
137. **JWT attacks suite** (grouped — 9 dedicated modules):
     `alg_none_attack.py`, `key_confusion.py`, `kid_injection.py`, `jku_x5u_injection.py`,
     `weak_secret.py`, `claim_manipulation.py`, `expiration_bypass.py`, `token_replay.py`,
     `_helpers.py`
138. **Auth bypass suite** (grouped — 8 modules):
     `analyzer.py`, `credential_stuffing.py`, `mfa_bypass.py`, `password_reset_abuse.py`,
     `privilege_escalation.py`, `session_fixation.py`, `token_manipulation.py`, `_helpers.py`
139. `active/brute_force/` — rate-limit bypass and cookie manipulation for brute-force scenarios
140. `active/race_condition/` — concurrent request race condition probes with timing analysis
141. `active/tenant_isolation/` — multi-tenant BOLA/BFLA probes with cross-tenant data access detection (6 sub-modules)
142. `accelerated_matcher.py` — compiled regex matcher with caching for high-throughput pattern matching

---

## Python Backend — Reconnaissance Engine

143. `recon/subdomains.py` — multi-source subdomain enumeration (DNS brute-force, certificate transparency, passive sources)
144. `recon/dns_enumerator.py` — async DNS resolution with record type coverage (A, AAAA, CNAME, MX, TXT, NS)
145. `recon/live_hosts.py` — HTTP/HTTPS probing with redirect following and status tracking
146. `recon/urls.py` — URL normalisation, deduplication, and parameter extraction
147. `recon/discovery.py` — top-level discovery coordinator across all recon sources
148. `recon/katana.py` — Katana web crawler integration with scope filtering
149. `recon/waf_cdn_detector.py` — WAF and CDN fingerprinting from response headers and patterns
150. `recon/takeover.py` — subdomain takeover detection via CNAME dangling checks
151. `recon/target_index.py` — indexed data structure for O(1) target lookup during scanning
152. `recon/scoring.py` + `ranking_support.py` — endpoint prioritisation scoring for scan ordering
153. `recon/js_discovery.py` + `js_fetcher.py` + `js_parsers.py` — JavaScript file discovery, fetch, and static analysis for secrets/endpoints
154. `recon/nuclei.py` + `nuclei_schema.py` — Nuclei runner with JSON schema validation of results
155. `recon/archive.py` — Wayback Machine and CommonCrawl historical URL discovery
156. `recon/standardize.py` — normalises heterogeneous recon output into unified `ReconResult` models
157. `recon/filters.py` — scope, extension, and content-type filters applied post-collection
158. `recon/gau_helpers.py` — GAU (Get All URLs) tool integration helpers
159. `recon/models.py` — Pydantic models for all recon data types
160. `recon/pipeline.py` — intra-recon sequential + parallel collection pipeline
161. **Recon collectors** (grouped — 6 modules):
     `aggregator.py`, `aggregator_stream.py`, `crawler.py`, `metrics.py`, `observability.py`, `rate_limiter.py`
162. **Archive providers**: Wayback Machine + CommonCrawl collectors with pagination support
163. **External providers**: OTX (AlienVault) and URLScan.io passive recon integrations
164. `recon/sources/rapiddns.py` + `virustotal.py` — RapidDNS and VirusTotal passive subdomain sources

---

## Python Backend — Detection & Intelligence

165. `detection/registry.py` — detection module registry with priority ordering
166. `detection/runtime.py` — runtime detector loader and hot-reload support
167. `detection/signals.py` — signal definitions for all detectable vulnerability classes
168. `intelligence/feeds/` — threat intelligence feed ingestion and normalisation
169. `intelligence/correlation/` — cross-finding correlation engine (chains related vulns into attack paths)
170. `intelligence/graph/` — graph-based attack-path modelling
171. `intelligence/scoring/` — compound risk scoring combining CVSS, exploitability, and business impact
172. `intelligence/campaigns/` — campaign tracking linking related findings across multiple runs

---

## Python Backend — Fuzzing Engine

173. `fuzzing/payload_generator.py` — context-aware payload generation for arbitrary parameter types
174. `fuzzing/payload_generator_http.py` — HTTP-specific payload mutations (headers, body, multipart)

---

## Python Backend — Exploitation & Validation

175. `execution/scenario_engine.py` — proof-of-concept scenario runner for confirmed vulnerabilities
176. `execution/scenario_models.py` — typed scenario definitions (steps, assertions, teardown)
177. `execution/exploiters/` — per-vulnerability-class automated exploitation modules
178. `execution/validators/` — automated output validators confirming exploit success/failure

---

## Python Backend — Reporting Engine

179. `reporting/html.py` — Jinja2-based HTML report generation with embedded charts
180. `reporting/sections.py` + `sections_general.py` + `sections_findings.py` — modular report section builders
181. `reporting/sections_campaigns.py` — campaign-level reporting section
182. `reporting/sections_graphs.py` — SVG chart injection into HTML reports
183. `reporting/sections_validation.py` — validation evidence section
184. `reporting/pages.py` — multi-page report assembly
185. `reporting/assets.py` — report asset embedding (CSS, fonts, logos)
186. `reporting/export_findings.py` — JSON/CSV export of raw findings
187. `reporting/compliance_mapping.py` — maps findings to OWASP Top 10, CWE, PCI-DSS, ISO 27001
188. `reporting/detection_coverage.py` — heatmap data for detection coverage across attack classes
189. `reporting/vrt_coverage.py` — Vulnerability Rating Taxonomy (VRT) coverage report
190. `reporting/pipeline.py` — report generation as a pipeline stage with output store integration

---

## Frontend — npm Dependencies

191. Upgraded `axios` ^1.14.0 → ^1.16.1
192. Upgraded `react` + `react-dom` ^19.2.4 → ^19.2.6
193. Upgraded `react-virtuoso` ^4.18.6 → ^4.18.7
194. Upgraded `dompurify` ^3.3.3 → ^3.4.3
195. Upgraded `eslint-plugin-react-hooks` ^7.0.1 → ^7.1.1
196. Upgraded `eslint-plugin-storybook` ^10.3.4 → ^10.4.0
197. Upgraded `storybook` + all `@storybook/*` packages ^10.3.4 → ^10.4.0 (6 packages)
198. Upgraded `postcss` ^8.5.8 → ^8.5.14
199. Upgraded `typescript` ~6.0.2 → ~6.0.3
200. Upgraded `@vitest/browser` ^4.1.2 → ^4.1.6
201. Upgraded `@types/dompurify` ^3.0.5 → ^3.2.0
202. `package-lock.json` regenerated after all version bumps
203. `vite ^8.0.3` — latest Vite build tooling
204. `typescript-eslint ^8.58.0` — latest TS-aware ESLint ruleset
205. `tailwindcss ^4.2.2` + `@tailwindcss/postcss ^4.2.2` — Tailwind v4 CSS engine
206. `framer-motion ^12.38.0` + `motion ^12.38.0` — animation library
207. `gsap ^3.14.2` — GreenSock animation for cinematic components
208. `three ^0.184.0` + `@react-three/fiber ^9.6.1` + `@react-three/drei ^10.7.7` — 3D visualisation stack
209. `recharts ^3.8.1` — charting library for findings dashboards
210. `react-router-dom ^7.14.0` — SPA routing
211. `react-hook-form ^7.72.1` + `@hookform/resolvers ^5.2.2` + `zod ^4.4.3` — form validation stack
212. `i18next ^26.0.3` + `react-i18next ^17.0.2` — internationalisation
213. `lucide-react ^1.7.0` — icon library
214. `@playwright/test ^1.59.1` + `playwright ^1.59.1` — E2E + visual regression testing
215. `vitest ^4.1.2` + `@vitest/coverage-v8` + `@vitest/ui` — unit test runner stack
216. `@testing-library/react ^16.3.2` + `@testing-library/user-event ^14.6.1` — component testing utilities
217. `lottie-react ^2.4.1` — Lottie animation support
218. `cmdk ^1.1.1` — command-palette primitive
219. `vaul ^1.1.2` — drawer component primitive
220. `embla-carousel-react ^8.6.0` — carousel component

---

## Frontend — API Client Layer

221. `api/client.ts` — base axios client with auth headers, timeout, and retry interceptors
222. `api/jobs.ts` — job lifecycle API (create, list, get, cancel, stream events)
223. `api/targets.ts` — target CRUD API
224. `api/findings.ts` — findings query API with filtering and pagination
225. `api/analysis.ts` — analysis results retrieval
226. `api/health.ts` — backend health polling
227. `api/reports.ts` — report download and listing
228. `api/schemas.ts` — OpenAPI schema introspection
229. `api/registry.ts` — scan module registry queries
230. `api/replay.ts` — HTTP request replay API
231. `api/retry.ts` — client-side retry logic with exponential backoff
232. `api/tracing.ts` — distributed trace retrieval
233. `api/export.ts` — findings export (CSV, JSON)
234. `api/notes.ts` — analyst notes CRUD
235. `api/security.ts` — security check configuration API
236. `api/cockpit.ts` — live ops cockpit data stream
237. `api/bloom.ts` — Bloom filter deduplication API
238. `api/cache.ts` + `api/cacheMgmt.ts` — cache inspection and management
239. `api/networkStatus.ts` — network connectivity status polling

---

## Frontend — Components

240. `AttackChainVisualizer.tsx` — interactive D3-force graph of attack chain relationships
241. `PipelineStageTimeline.tsx` — animated Gantt-style pipeline stage progress timeline
242. `LiveTerminalFeed.tsx` — virtualized (react-virtuoso) real-time log stream
243. `JobList.tsx` — sortable, filterable job list with live status indicators
244. `FindingsOverview.tsx` — findings summary with severity breakdown and trend sparklines
245. `ReconResults.tsx` — tabbed recon results viewer (subdomains, URLs, hosts, JS files)
246. `RemediationSuggestions.tsx` — per-finding remediation guidance panel
247. `RemediationTracker.tsx` — persisted remediation status tracker
248. `RequestResponseViewer.tsx` — HTTP request/response diff viewer with syntax highlighting
249. `ReplayInterface.tsx` — request replay UI with header/body editing
250. `EvidenceDisplay.tsx` — structured evidence viewer (screenshots, payloads, responses)
251. `CVSSDetail.tsx` — CVSS v3.1 score breakdown with vector string display
252. `AuditLogViewer.tsx` — tamper-evident audit log with hash chain verification
253. `ComplianceLogViewer.tsx` — compliance event log filtered by standard (OWASP, PCI, ISO)
254. `ChainOfCustodyViewer.tsx` — evidence chain of custody timeline
255. `RunDiffViewer.tsx` — diff view between two job runs (new/fixed/persisting findings)
256. `ScanSummaryCard.tsx` — compact scan result summary card with severity badges
257. `ScanPresets.tsx` — saved scan preset selector and manager
258. `PluginProgressGrid.tsx` — grid view of active plugin execution status
259. `IterationProgressBar.tsx` — animated progress bar for multi-iteration scans
260. `DurationForecast.tsx` — ETA forecast display using `eta_engine.py` estimates
261. `NotificationCenter.tsx` — slide-in notification panel with per-category filtering
262. `CommandPalette.tsx` — `cmdk`-powered global command palette (Ctrl+K / Cmd+K)
263. `OnboardingTour.tsx` — step-by-step onboarding walkthrough for new users
264. `HealthIndicator.tsx` — live backend health indicator with animated pulse
265. `LiveJobIndicator.tsx` + `LivePipelineStatus.tsx` — real-time job and pipeline status badges
266. `SessionLock.tsx` — idle-timeout session lock screen
267. `PIIControls.tsx` — PII redaction toggle and scope controls
268. `PerformanceDashboard.tsx` — Web Vitals + backend latency combined performance view
269. `DashboardTrendCharts.tsx` — multi-series trend charts (findings over time, scan frequency)
270. `ErrorBoundary.tsx` — React error boundary with graceful fallback UI
271. `CopyButton.tsx` — clipboard copy button with success feedback
272. `Icon.tsx` — centralised icon wrapper mapping lucide-react icons by name
273. `FormField.tsx` — accessible form field wrapper with label, error, and hint text
274. `FocusTrap.tsx` — keyboard focus trap for modals and drawers
275. `RouteFocusManager.tsx` + `RouteFocus.tsx` — announces route changes to screen readers
276. `RouteGuard.tsx` — role-based route protection HOC
277. `AccessibleEmoji.tsx` — emoji wrapper with proper `aria-label` and `role="img"`
278. `LiveAnnouncer.tsx` — ARIA live region announcer for dynamic content changes
279. `LanguageSelector.tsx` — i18n language switcher
280. `LogLine.tsx` — single log line with ANSI colour parsing
281. `InstallPrompt.tsx` + `common/PWAInstallPrompt.tsx` — PWA install prompt (deduped into one)
282. `common/WebVitalsDashboard.tsx` — Core Web Vitals at-a-glance panel
283. `common/RoleGates.tsx` — conditional render gates by user role
284. `common/EvidenceCustodyViewer.tsx` — shared evidence custody component
285. **Charts** (grouped — 4 chart components):
     `FindingsRadarChart.tsx`, `SeverityTrendChart.tsx`, `ModulePerformanceChart.tsx`, `StageDurationHeatmap.tsx`
286. **Motion / cinematic components** (grouped — 4):
     `CinematicIntro.tsx`, `MicroPulseValue.tsx`, `PageTransition.tsx`, `StatePulse.tsx`
287. **Ops components** (grouped — 3):
     `BloomMeshHealthPanel.tsx`, `StageTheater.tsx`, `ThroughputStrip.tsx`
288. **Job wizard steps** (grouped — 6 step components):
     `TargetStep.tsx`, `ModulesStep.tsx`, `ConfigStep.tsx`, `ReviewStep.tsx`, `JobStatusHeader.tsx`, `JobLogViewer.tsx`
289. `jobs/StartJobForm.tsx` + `useJobFormState.ts` — multi-step job creation form with validation
290. **Settings sections** (grouped — 16 settings panels):
     About, Accessibility, API, Dashboard, Data, Display, Experimental, Integrations, Language, Notifications, Performance, Pipeline, Reports, ScanProfiles, Security, + index barrel
291. `layout/AppLayout.tsx` — top-level shell layout with sidebar, header, and content area
292. `AnalysisOptionsPanel.tsx` — scan module toggle and weight configuration panel
293. `FindingComments.tsx` — per-finding threaded comment system
294. `PageTransition.tsx` (root) — page-level Framer Motion transition wrapper

---

## Frontend — Pages & Routing

295. Full SPA with `react-router-dom v7` — nested routes with lazy loading
296. Job detail page with tabbed sections (Overview, Findings, Logs, Evidence, Timeline)
297. Findings list page with server-side pagination, sort, and multi-filter
298. Target management page with bulk import and validation
299. Reports page with download links and format selection
300. Settings page with 16 categorised sections
301. Tracing page — distributed trace waterfall viewer
302. Live ops cockpit — real-time pipeline health, throughput, and Bloom mesh status

---

## Frontend — Hooks & Utilities

303. `useJobMonitor` — subscribes to job WebSocket stream with reconnect on disconnect
304. `useFindingsTimeline` — derives findings trend data from job history
305. `useRiskHistory` — historical risk score timeline hook
306. `utils/auditLogger.ts` — client-side audit event recorder with local persistence
307. `utils/chainOfCustody.ts` — evidence chain builder and verifier
308. `utils/complianceLogger.ts` — compliance event logger keyed by standard
309. `utils/evidenceChain.ts` — cryptographic evidence chain utilities
310. `utils/piiRedactor.ts` — regex-based PII redaction applied before any display
311. `utils/sanitizeContent.ts` — DOMPurify-backed HTML sanitiser wrapper
312. `utils/sessionTimeout.ts` — idle detection and automatic session lock trigger
313. `utils/notificationDigest.ts` — digest batching for high-frequency notifications
314. `utils/notifications.ts` — notification store with read/unread state
315. `utils/rolePermissions.ts` — role → permission mapping used by `RoleGates`
316. `utils/storage.ts` — typed localStorage wrapper with JSON serialisation
317. `utils/threatIntelligence.ts` — client-side threat intel cache and lookup helpers
318. `utils/visibilityManager.ts` — Page Visibility API wrapper for pausing background polling
319. `utils/webVitals.ts` — Web Vitals collection and reporting to backend analytics endpoint
320. `utils/moduleDependencies.ts` — scan module dependency graph for wizard UI
321. `utils/errorOverlay.ts` + `utils/errorTracker.ts` — client-side error capture and overlay display
322. `utils/init.ts` — application bootstrap sequence (auth check, feature flags, i18n init)
323. `utils/pwa.ts` — PWA service worker registration and update notification
324. `workers/findingsProcessor.ts` — Web Worker for off-main-thread findings processing

---

## Frontend — Tests

325. `tests/unit/Badge.test.tsx`, `Button.test.tsx`, `Input.test.tsx`, `Modal.test.tsx`, `DataTable.test.tsx` — component unit tests
326. `tests/unit/apiRetry.test.ts` — retry interceptor unit tests covering backoff and abort
327. `tests/unit/mapToVisualState.test.ts` — visual state mapping pure-function tests
328. `tests/unit/utils.test.ts` — utility function unit tests
329. `tests/unit/motionPolicy.test.ts` — reduced-motion preference enforcement tests
330. `tests/unit/themeMotionContext.test.tsx` — theme and motion context integration tests
331. `tests/unit/JobDetailPage.reconFailure.test.tsx` — recon failure handling in job detail view
332. `tests/unit/useJobMonitor.reconFailure.test.ts` — hook behaviour on recon stage failure
333. `tests/unit/PipelineStageTimeline.stageContract.test.tsx` — stage contract assertions
334. `tests/unit/StageTheater.stageContract.test.ts` — StageTheater contract tests
335. `tests/unit/useFindingsTimeline.test.tsx` + `useRiskHistory.test.tsx` — timeline hook tests
336. `tests/setup.ts` — Vitest global setup with `@testing-library/jest-dom` matchers

---

## Frontend — Accessibility

337. All interactive elements audited with `eslint-plugin-jsx-a11y`
338. `FocusTrap` applied to all modals, drawers, and command palette
339. `LiveAnnouncer` provides ARIA live region updates for async state changes
340. `RouteFocusManager` shifts focus to main content on every route transition
341. `AccessibleEmoji` wraps all decorative emoji with `role="img"` and `aria-label`
342. Colour contrast ratios verified across all theme tokens in `styles/system/tokens.css`
343. Keyboard navigation tested for all interactive components via Playwright
344. `reduced-motion` media query respected by all Framer Motion and GSAP animations

---

## Frontend — Styling System

345. Design token system in `styles/system/tokens.css` — colour, spacing, typography, radius, shadow
346. Component styles split into 11 dedicated CSS files under `styles/system/components/`
347. Layout styles split across `header.css`, `sidebar.css`, `shell.css`, `mobile.css`
348. Page-specific styles: `findings.css`, `settings.css`, `targets.css`, `tracing.css`, `auth.css`
349. `styles/system/motion.css` — standardised animation durations and easing curves
350. Tailwind v4 utility classes layered over design token base

---

## Frontend — Internationalisation

351. `i18next` integration with `react-i18next` for all user-visible strings
352. `LanguageSelector` component exposed in settings and header
353. Translation namespace split by feature area (jobs, findings, settings, common)

---

## Configuration & Deployment

354. `configs/grafana/provisioning/dashboards/dashboard.yml` — auto-provisions Singularity-Zero Grafana dashboard
355. `configs/grafana/provisioning/datasources/datasource.yml` — Prometheus datasource auto-provisioned
356. `deploy/prometheus-docker.yml` — Prometheus scrape config targeting backend metrics endpoint
357. `docker-compose.yml` — full dev stack (backend, frontend, Prometheus, Grafana)
358. `docker-compose.optimized.yml` — production-optimised compose without dev tooling
359. `alembic/env.py` — Alembic migration environment for any DB-backed features
360. `_audit_runner.py` — standalone audit runner script for CI security gate integration

---

*Total: 360 entries — similar/identical changes consolidated into single entries throughout.*
