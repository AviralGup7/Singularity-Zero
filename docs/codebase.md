# Codebase Map & Module Directory

This document provides a comprehensive, ground-truth structural map of the Cyber Security Test Pipeline codebase, detailing package responsibilities, key submodules, contracts, and cross-cutting dependencies.

---

## 📂 Root Project Structure

```text
.
├── src/                  # Core Python backend engine, services, and domain packages
├── frontend/             # Operator command center (React 19 + TypeScript + Tailwind 4 + R3F)
├── tests/                # Test suites (unit, integration, architecture, regression)
├── configs/              # System configurations, Grafana provisioning, SBOM/OpenAPI baselines
├── deploy/               # Deployment specifications (Terraform, Kubernetes, Docker Compose)
├── scripts/              # CI/CD verification, audit, and debugging utilities
├── alembic/              # Database schema migrations
├── pyproject.toml        # Build configuration, package metadata, tool configs (ruff, mypy, pytest)
├── docker-compose.yml    # Full-stack composition (API, Redis, Postgres, Grafana, Prometheus)
└── Makefile              # Convenience targets for build, test, lint, and run
```

---

## 🐍 Backend Subsystem (`src/`)

The Python backend is organized into domain-specific modules adhering to explicit contract boundaries and dependency rules:

```text
src/
├── analysis/             # 🧠 Cognitive & automated vulnerability analyzers
│   ├── active/           # Active scanning modules (SQLi, XSS, SSRF, JWT, CSP bypass, HTTP smuggling)
│   ├── passive/          # Passive inspection of traffic, headers, and responses
│   ├── automation/       # Autonomous orchestration of multi-step vulnerability discovery
│   ├── behavior/         # Application behavioral profiling and baseline modeling
│   ├── bug_bounty/       # Bug-bounty platform scope integration and report formatting
│   ├── checks/           # Modular security check definitions
│   ├── intelligence/     # Lateral graph, IDOR/BAC prober, semantic deduplication, CSI
│   ├── json/             # JSON parsing and schema extraction
│   ├── plugins/          # Third-party and built-in analysis plugins
│   ├── plugin_runtime/   # Dynamic plugin executor and lifecycle management
│   └── response/         # Response classification, diffing, and anomaly scoring
│
├── api_tests/            # 🧪 API-key candidate checklist and stored-result formatting (not GraphQL/gRPC/fuzzing)
│   ├── apitester/        # Core API test harness and scenario runners
│   ├── api_tester.py     # Unified API test orchestrator
│   └── __main__.py       # Standalone CLI entrypoint for API testing
│
├── auth/                 # 🔐 Authentication, authorization, RBAC, and session management
│   ├── audit.py          # Auth event logging and security auditing
│   ├── capabilities.py   # Token capability validation and scope enforcement
│   ├── demo.py           # Demo mode authentication provider
│   ├── policy.py         # RBAC policy definitions and rules
│   ├── rbac.py           # Role-based access control engine
│   ├── session.py        # Session token generation and revocation
│   └── sessions.py       # Distributed session store integration
│
├── bootstrap/            # ⚡ Application startup lifecycle and dependency wiring
│   └── startup_registration.py # Pre-flight registry and subsystem initialization
│
├── cache/                # ⚡ High-performance unified caching interfaces
├── checkpoint/           # 💾 Distributed scan state snapshot and recovery interfaces
│
├── cli/                  # 💻 Modern CLI terminal command center
│   ├── commands/         # Subcommand definitions (scan, orchestrate, mesh, worker, replay, export)
│   ├── types.py          # CLI type definitions and argument parsing models
│   └── ui.py             # Rich terminal rendering, spinners, and formatted tables
│
├── console/              # 🎮 Interactive operator console backend and playbooks
│   ├── handlers/         # Console action handlers and command routers
│   ├── gateway.py        # Gateway for console client connections
│   ├── playbook.py       # Automated response playbooks and triage workflows
│   └── runtime.py        # Operator console execution runtime
│
├── core/                 # 🏛️ Foundational domain models, contracts, and core utilities
│   ├── contracts/        # Immutable Pydantic models and stage input/output schemas
│   ├── frontier/         # Low-level frontier state, CRDTs, Bloom filters, and WAL
│   ├── models/           # Shared domain entities (Job, Finding, Target, Evidence)
│   ├── security/         # Cryptographic primitives, Ed25519 signatures, AES-GCM vault
│   ├── utils/            # Shared helpers (HTTP pools, timezones, streaming, URL validator)
│   ├── concurrency_governor.py # Dynamic thread and task concurrency throttler
│   └── tenant_context.py # contextvars-based multi-tenant isolation
│
├── dashboard/            # 📊 FastAPI REST API and WebSocket dashboard service
│   ├── fastapi/          # REST route handlers, dependencies, and FastAPI application entrypoint
│   ├── config/           # Dashboard configuration and feature flag descriptors
│   ├── controls/         # Interactive scan controls and runtime parameter overrides
│   ├── forensics/        # Forensic evidence bundling and export services
│   ├── services/         # Dashboard business logic services (jobs, findings, analytics)
│   └── eta_engine.py     # Live job duration and completion estimation engine
│
├── decision/             # 🎯 Adaptive attack planning, scan budgeting, and contract of intent
│   ├── attack_selection/ # Attack path ranking and payload selection heuristics
│   ├── prioritization/   # Target vulnerability scoring and queue prioritization
│   ├── adaptive_scan.py  # Closed-loop scan depth and concurrency adaptation
│   ├── authorization.py  # ScopeToken verification and AuthorizedExecutionTicket issuer
│   ├── hunt_budget.py    # Request and execution budget allocations
│   ├── models.py         # Domain models (ExecutionRequest, TargetSpec, ActionSpec, ScopeToken, ExecutionResult)
│   └── planner.py        # Dynamic attack DAG planner
│
├── detection/            # 🔍 Signature detection, rule catalog, and finding management
│   ├── api/              # API detection rules and schema validators
│   ├── ast/              # Abstract Syntax Tree source analysis
│   ├── browser/          # Headless browser detection and DOM mutation observers
│   ├── timing/           # Time-based blind vulnerability detection (SQLi/Command Injection)
│   ├── waf/              # Web Application Firewall fingerprinting and evasion matrix
│   ├── catalog.py        # Central vulnerability signature catalog
│   ├── finding.py        # Finding entity lifecycle and normalization
│   └── mode_matrix.py    # Detection execution mode matrix (Safe, Aggressive, Stealth)
│
├── execution/            # ⚙️ Exploit and payload execution scenarios
│   ├── auth/             # Execution authentication token exchange
│   ├── exploiters/       # Exploit execution modules
│   ├── remediators/      # Automated remediation advice generators
│   ├── request_executor.py # Stateless ExecutionRequestWorker executing against contracts of intent
│   ├── scenario_engine.py# Multi-stage scenario validation and replay
│   └── waf_probe_adapter.py # Adapter for WAF probe responses
│
├── exploitation/         # 💥 Exploit engines, protocol fuzzers, and validators
│   ├── engines/          # Specialized exploit execution engines
│   ├── grpc/             # gRPC protocol probing, reflection, and exploit suite
│   ├── payloads/         # Polymorphic payload generator and encoding chains
│   ├── ssrf/             # Server-Side Request Forgery probing and metadata exfiltration
│   ├── takeover/         # Subdomain takeover verification (DNS, S3, Azure, CloudFront)
│   ├── http2_smuggling.py# HTTP/2 multiplexing, desync, and smuggling exploits
│   └── websocket_fuzzer.py # WebSocket frame mutation and fuzzing engine
│
├── frontier/             # 🧭 Scan frontier state, CRDTs, journal, and verification
│   ├── deltas.py         # State mutation delta calculation and validation
│   ├── journal.py        # Append-only journal for state change auditing
│   ├── merge.py          # Conflict-free state delta merge engine
│   └── verify.py         # State integrity, hash validation, and CRC attestation
│
├── fuzzing/              # 🎲 High-throughput payload mutation and differential fuzzers
│   ├── generators/       # Payload generation strategies (grammar, dictionary, regex)
│   ├── ast_mutator.py    # AST-guided payload transformation
│   ├── coverage_guided.py# Feedback-driven mutation coverage optimizer
│   ├── differential_fuzzer.py # Differential HTTP response fuzzer
│   └── graphql_fuzzer.py # GraphQL query complexity and injection fuzzer
│
├── infrastructure/       # 🏗️ Platform infrastructure and distributed systems
│   ├── cache/            # Distributed Redis cache and SQLite fast local cache
│   ├── checkpoint/       # Checkpoint storage (Redis, Local AOF, Cloud Storage)
│   ├── db/               # SQLAlchemy models and connection lifecycle
│   ├── discovery/        # Node discovery and peer health tracking
│   ├── execution_engine/ # Async task pool, worker concurrency, load balancer
│   ├── mesh/             # P2P Actor Mesh, SWIM gossip, consensus, and sharding
│   ├── notifications/    # Slack, Discord, Email, and Webhook dispatchers
│   ├── observability/    # Prometheus metrics, OpenTelemetry tracing, structured logging
│   ├── queue/            # Redis Streams & Celery/RQ job queues
│   └── security/         # Cryptographic signing, TLS cert management, rate limiting
│
├── integration/          # 🔗 Cross-system orchestration, idempotency, and envelope translation
│   ├── authz.py          # Cross-boundary authorization checks
│   ├── batch.py          # Batch operation envelope builders
│   ├── correlation.py    # Request correlation ID tracking across threads/async tasks
│   └── idempotency.py    # Idempotent scan task execution locks
│
├── intel/                # 🕵️ Threat intelligence aggregation and IOC feeds
│   ├── aggregator.py     # Multi-source threat intel aggregator
│   ├── feeds.py          # OTX, Shodan, VirusTotal, NVD, and CISA KEV feed parsers
│   ├── ioc.py            # Indicator of Compromise matching and extraction
│   └── watchlist.py      # Target and IP asset watchlists
│
├── intelligence/         # 🧠 Active learning, severity scoring, and threat modeling
│   ├── campaigns/        # Threat campaign tracking and attribution
│   ├── correlation/      # Multi-stage finding correlation engine
│   ├── graph/            # Attack-graph model and path discovery
│   ├── scoring/          # Composite Severity Index (CSI), EPSS, CVSS calculator
│   └── swarm/            # Multi-agent collaborative security testing swarm
│
├── jobs/                 # 📋 Job execution lifecycle, history, artifacts, and comparisons
│   ├── artifacts.py      # Scan artifact archiving (SARIF, JSON, PDF, PCAP)
│   ├── compare.py        # Finding diff and regression detection between scan runs
│   ├── eta.py            # Real-time job ETA and progress computation
│   └── history.py        # Historic scan execution retrieval and filtering
│
├── learning/             # 🎓 Closed-loop feedback, threshold auto-tuning, and policy calibration
│   ├── config/           # Calibration hyperparameters and feature configurations
│   ├── models/           # Calibrated severity scoring models and feature weights
│   ├── repositories/     # Triage label and feedback persistence repositories
│   ├── baseline_tracker.py # Scan target baseline variance tracking
│   ├── feedback_loop.py  # Closed-loop triage signal and threshold adaptation
│   ├── finding_deduplicator.py # Semantic finding deduplication (TF-IDF/Cosine)
│   ├── nuclei_tag_optimizer.py # Dynamic Bayesian Beta-Binomial Nuclei template tag ranking
│   ├── threshold_tuner.py# PI-controller automatic threshold calibration
│   └── versioned_policy.py# Immutable VersionedPolicy container for priority queue tuning
│
├── mesh/                 # 🕸️ Actor Mesh interfaces and distributed state sharing
├── notifications/        # 📬 Notification routing, escalation policies, and digest grouping
│   ├── escalation.py     # Alert escalation matrices for Critical findings
│   ├── inbox.py          # In-app notification center inbox
│   └── routing.py        # Rule-based alert routing (Severity, Target, Compliance)
│
├── pipeline/             # 🔀 Distributed DAG Orchestrator and stage lifecycle
│   ├── constants/        # Pipeline stage names, exit codes, and status enums
│   ├── parallel_analysis/# Parallel stage execution coordination
│   ├── retry/            # Exponential backoff and Retry-After policy handlers
│   ├── self_healing/     # Dynamic failure recovery, stage skipping, and re-routing
│   ├── services/         # Orchestrator core services:
│   │   └── pipeline_orchestrator/ # DAG builder, actor scheduler, stage executors
│   └── unified_cache/    # Integrated cross-stage result caching
│
├── realtime/             # 📡 Real-time telemetry and state distribution interfaces
│
├── recon/                # 🌐 Asset discovery and reconnaissance engines
│   ├── api_specs/        # OpenAPI/Swagger, WSDL, and GraphQL schema reconstructors
│   ├── cloud_recon/      # AWS S3, Azure Blob, GCP bucket, and CloudFlare discoverers
│   ├── collectors/       # Passive OSINT collectors (AlienVault, Wayback, Sublist3r)
│   ├── graphql/          # GraphQL endpoint detection and introspection crawler
│   ├── js_parsers/       # JavaScript AST parser, secret extractor, and route finder
│   ├── live_hosts/       # Fast ICMP/TCP/HTTP port probing and service identification
│   └── sources/          # Domain, DNS, WHOIS, and certificate transparency sources
│
├── reporting/            # 📄 Multi-format vulnerability reporting and compliance
│   ├── platforms/        # Bugcrowd, HackerOne, DefectDojo, and Jira exporters
│   ├── compliance_attestation.py # SOC 2, ISO 27001, PCI-DSS compliance attestations
│   ├── compliance_pdf.py # Cryptographically signed PDF report generator
│   └── exporters.py      # SARIF, CSV, JSON, Markdown, HTML export handlers
│
├── resilience/           # 🛡️ High-availability circuit breakers, retry handlers, and probes
│   ├── circuit_breaker.py# 3-state Circuit Breaker (Closed, Open, Half-Open)
│   ├── metrics.py        # Circuit breaker state metrics and trip counters
│   ├── persistence.py    # Circuit breaker state persistence (Redis/Local)
│   └── retry_after.py    # HTTP 429 Retry-After header parsing and backoff override
│
├── sandbox/              # 📦 Isolated execution sandbox (Wasmtime WASM & Subprocess)
│
└── websocket_server/     # 🔌 Real-time WebSocket streaming server
    ├── broadcaster.py    # Channel-based event broadcast multiplexer
    ├── handlers.py       # Message handlers for subscriptions and control commands
    ├── heartbeat.py      # WebSocket connection health probes and keepalive
    ├── manager.py        # Active connection registry and backpressure limiter
    └── protocol.py       # Binary MessagePack and JSON WebSocket wire protocol
```

---

## 🎨 Frontend Subsystem (`frontend/src/`)

Built with React 19, TypeScript, Tailwind CSS 4, React Three Fiber, and Zustand:

```text
frontend/src/
├── api/                  # Typed API client functions and Axios/Fetch wrappers
│   ├── jobs.ts           # Job lifecycle, trigger, pause, resume, cancel endpoints
│   ├── findings.ts       # Finding queries, triage updates, bulk actions, notes
│   ├── targets.ts        # Target asset management and scope definitions
│   ├── mesh.ts           # Distributed mesh nodes, health, and HLC clock status
│   └── analytics.ts      # Trend metrics, vulnerability distribution, severity curves
│
├── components/           # Reusable UI component library
│   ├── common/           # Generic buttons, badges, modals, inputs, tooltips
│   ├── console/          # Operator terminal, interactive CLI, and command drawer
│   ├── layout/           # Sidebar navigation, top header, breadcrumbs, status bar
│   ├── motion/           # Motion graphics and smooth transition wrappers
│   ├── ops/              # Stage theater, execution timelines, live log viewers
│   └── three/            # 3D InstancedMesh threat visualization cockpit
│
├── context/              # React context providers (Auth, Theme, Sound, Keybindings)
├── hooks/                # Custom React hooks (useWebSocket, useJobMonitor, useFindings, useTheme)
├── i18n/                 # Localization dictionaries and language provider
├── lib/                  # Utility libraries, formatting, date helpers, sanitizers
├── pages/                # Top-level view routes:
│   ├── DashboardPage.tsx # Executive security dashboard and primary KPI cards
│   ├── JobsPage.tsx      # Active and historic scan jobs with live progress
│   ├── JobDetailPage.tsx # Deep-dive job view with StageTheater and live log stream
│   ├── FindingsPage.tsx  # Interactive vulnerability table with filters and triage
│   ├── FindingDetailPage.tsx # Finding evidence, request/response replay, remediation
│   ├── TargetsPage.tsx   # Target inventory, asset tagging, and scope boundaries
│   ├── AnalyticsPage.tsx # Longitudinal vulnerability trends and risk heatmaps
│   ├── MeshPage.tsx      # Distributed node topology and Bloom filter synchronization
│   ├── ConsolePage.tsx   # Operator command center and automated playbooks
│   ├── CockpitPage.tsx   # 3D interactive threat graph visualization
│   └── SettingsPage.tsx  # System parameters, API keys, and notification sinks
│
├── stores/               # Zustand global state stores (useJobStore, useFindingsStore, useMeshStore)
├── styles/               # Global CSS, theme definitions, and Tailwind 4 directives
├── types/                # Shared TypeScript contracts and schema interfaces
└── workers/              # Web Workers for client-side search, sorting, and graph layout
```

---

## 🧪 Test Suites (`tests/`)

```text
tests/
├── unit/                 # Unit tests for individual classes, functions, and analyzers
│   ├── analysis/         # Security analyzer tests
│   ├── auth/             # Authentication and RBAC tests
│   ├── cli/              # Command line argument parser and output tests
│   ├── core/             # Core contracts, utilities, and crypto tests
│   ├── dashboard/        # FastAPI endpoints and route handlers
│   ├── exploitation/     # Exploit engine payload generation tests
│   ├── learning/         # ML model training, deduplication, and feedback tests
│   ├── pipeline/         # DAG graph builder, scheduler, and retry logic
│   └── recon/            # Recon collectors, DNS, and parsing tests
│
├── integration/          # Multi-component integration tests (Redis, DB, Orchestrator)
├── architecture/         # Layer boundary and import linter architecture assertions
└── regression/           # Fixed bug regression and contract attestation tests
```

---

## 📐 Architecture Rules & Conventions

1. **Strict Layer Boundary Isolation**:
   - `core` cannot import from `pipeline`, `analysis`, or `dashboard`.
   - `analysis` and `recon` communicate with the pipeline via `StageInput` and `StageOutput` contracts.
   - All state mutations are emitted as immutable deltas; no in-place modification of shared state.
2. **Type Safety & Validation**:
   - All external API and CLI boundaries validate inputs using `Pydantic v2` / `Zod`.
   - All critical internal interfaces are type-annotated and verified by `pyright` / `mypy`.
3. **Resilience by Default**:
   - External network calls must be wrapped with `CircuitBreaker` and dynamic `RetryAfter` backoff.
