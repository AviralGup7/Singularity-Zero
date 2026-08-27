# Codebase Map & Module Directory

This document provides a comprehensive, ground-truth structural map of the Cyber Security Test Pipeline codebase, detailing package responsibilities, key submodules, contracts, and cross-cutting dependencies. For the formal authority planes, disambiguation rules, and consolidation contracts across all 32 top-level packages, see **[Codebase Consolidation Architecture](architecture/code-consolidation.md)**.

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
│   ├── automation/       # Autonomous orchestration of multi-step vulnerability discovery
│   ├── behavior/         # Application behavioral profiling and baseline modeling
│   ├── bug_bounty/       # Bug-bounty platform scope integration and report formatting
│   ├── checks/           # Modular passive and active security check definitions (headers, cookies, CORS, secrets)
│   ├── intelligence/     # Lateral graph, IDOR/BAC prober, finding_explainer (AI personas), semantic deduplication, CVSS v3.1 scoring, decision engine
│   ├── json/             # JSON parsing and schema extraction
│   ├── passive/          # Passive inspection of traffic, headers, and responses
│   ├── plugins/          # Third-party and built-in analysis plugin registries
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
│   ├── commands/         # Subcommand definitions (scan, start, system, plugin)
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
│   ├── contracts/        # Immutable models: CommandEnvelope, CommittedEntry, CommandReceipt, CanonicalTargetIdentity, ExecutionAuthorizationTuple
│   ├── frontier/         # Partitioned Raft core & coordination:
│   │   ├── authority_runtime.py # In-process PipelineAuthorityRuntime bundle & CLI binding
│   │   ├── commands.py       # Typed formal commands (reserve_global_budget, allocate_sublease, etc.)
│   │   ├── global_coordination.py # P-0000 GlobalBudgetAggregate, GlobalRunAggregate, PlacementAuthority
│   │   ├── invariant_checker.py # 16 Formal System Invariants machine-checkable verification suite
│   │   ├── lease_status.py   # Canonical LeaseStatus FSM, transition validators & I28 lifecycle
│   │   ├── outbox.py         # DurableOutboxLedger & CommittedOutboxStream with CRC-64 persistence & deduplication
│   │   ├── partition_authority.py # Partition router & lease fencing validator
│   │   ├── projection_stream.py # ProjectionCheckpointVector & CommittedLogConsumer with gap detection
│   │   ├── raft_fsm.py       # Pure deterministic PartitionFSM, aggregates, idempotency index, CertifiedSnapshot
│   │   ├── raft_transport.py # Raft RPC protocol & InMemoryRaftTransport / NetworkRaftTransport routers
│   │   ├── receipt_crypto.py # HMAC-SHA256 command receipt signing & constant-time verification (I13)
│   │   ├── replicated_log.py # Per-partition Raft log, PartitionWAL (CRC-64 + fsync), quorum validation, leader receipts
│   │   ├── replay_engine.py  # Deterministic WAL replay & schema upcaster runner
│   │   ├── run_saga.py       # DurableRunSagaEngine multi-partition workflow coordinator
│   │   ├── state_authority.py # Authoritative state and settlement coordinator (`settle_stage_output`)
│   │   ├── state.py          # NeuralState & CRDT LWW-set representations (`findings` + `candidates`)
│   │   ├── invariant_graph.py # I22/I28/I30–I37 proof graph (bidirectional edges)
│   │   ├── global_invariants.py # I30–I32 assertions
│   │   ├── causal_identity.py # I33 CommandId→DeliveryId
│   │   ├── event_delivery.py # Outbox-before-bus FINDING_CREATED
│   │   ├── settlement_receipt.py # HMAC receipt stamp/verify (no self-attested authoritative)
│   │   ├── failure_model.py  # I34 recovery table
│   │   ├── recovery_protocol.py # I35 state machine
│   │   ├── region_model.py   # I36 single-writer regions
│   │   ├── authority_transfer.py # I37 OWNED→FENCED→OWNED
│   │   └── wal_errors.py     # Fail-closed WALCorruptionError definition
│   ├── models/           # Shared domain entities (Job, Finding, Target, Evidence)
│   ├── security/         # Cryptographic primitives, Ed25519 signatures, AES-GCM vault, canonical Merkle roots
│   ├── storage/          # CAS content-addressable storage store (CASStore)
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
│   ├── authorization.py  # ScopeToken verification, canonical identity pinning, and AuthorizedExecutionTicket issuer
│   ├── bayesian_bandit.py# Multi-Armed Bayesian Bandit with Thompson Sampling and UCB1 exploration
│   ├── hunt_budget.py    # Multi-axis resource cap enforcer with atomic request reservation
│   ├── models.py         # Domain models (ExecutionRequest, TargetSpec, ActionSpec, ScopeToken, ExecutionResult)
│   └── planner.py        # Dynamic attack DAG planner
│
├── detection/            # 🔍 Signature detection, rule catalog, and finding management
│   ├── api/              # API detection rules and schema validators
│   ├── ast/              # Abstract Syntax Tree JavaScript sink analyzer, prototype pollution walker, WASM introspector
│   ├── browser/          # Headless browser runtime and dynamic DOM-XSS mutation observers
│   ├── timing/           # Statistical time-based blind vulnerability detection
│   ├── waf/              # WAF fingerprinting, challenge handlers, and Hidden Markov Model (HMM) evader
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
│   ├── generators/       # Payload generation strategies (grammar, dictionary, regex, protobuf, xml, jwt)
│   ├── ast_mutator.py    # AST-guided JSON and grammar payload transformation
│   ├── coverage_guided.py# CorpusManager & CoverageTracker feedback-driven mutation coverage optimizer
│   ├── differential_fuzzer.py # Differential HTTP response fuzzer
│   ├── fork_server.py    # Native process ForkServer execution with crash and anomaly containment
│   ├── graphql_fuzzer.py # GraphQL query complexity and injection fuzzer
│   ├── h2_fuzzer.py      # HTTP/2 frame stream and multiplexing fuzzer
│   └── quic_fuzzer.py    # QUIC / UDP packet and transport fuzzer
│
├── infrastructure/       # 🏗️ Platform infrastructure and distributed systems
│   ├── cache/            # Distributed Redis cache and SQLite fast local cache
│   ├── checkpoint/       # Checkpoint storage (Redis, Local AOF, Cloud Storage)
│   ├── db/               # SQLAlchemy models and connection lifecycle
│   ├── discovery/        # Node discovery and peer health tracking
│   ├── execution_engine/ # Async task pool, worker concurrency, load balancer
│   ├── flow_control/     # Closed-loop AdaptivePIDController, concurrency BulkheadPool, and CircuitBreaker
│   ├── frontier/         # Ghost Actor VFS, Bloom Mesh synchronization, and distributed WAL
│   ├── mesh/             # P2P Actor Mesh, SWIM gossip, heartbeat failure detector, and task auction bidder
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
│   ├── correlation/      # Multi-stage finding correlation and attack chain diff engine
│   ├── feeds/            # External intelligence connector feeds (CISA KEV, EPSS, Shodan, MISP, OTX, VT)
│   ├── graph/            # Attack-graph model and Dijkstra shortest attack path discovery
│   ├── risk/             # ThreatIntelEnricher, CISA KEV, EPSS, CVSS v4, and ModernRiskEngine
│   ├── scoring/          # Composite Severity Index (CSI), risk scoring engine
│   └── swarm/            # Multi-agent collaborative security testing swarm
│
├── jobs/                 # 📋 Job execution lifecycle, history, artifacts, and comparisons
│   ├── artifacts.py      # Scan artifact archiving (SARIF, JSON, PDF, PCAP)
│   ├── compare.py        # Finding diff and regression detection between scan runs
│   ├── eta.py            # Real-time job ETA and progress computation
│   ├── history.py        # Historic scan execution retrieval and filtering
│   ├── simulator.py      # Scan dry-run and pipeline flow simulator
│   ├── stage_machine.py  # Strict stage lifecycle state machine
│   ├── status.py         # JobStatus SM — only `_transition` writes; lowercase values
│   ├── run_outcome.py    # `derive_job_and_exit` lattice (0/2/4/3/1/7/130)
│   └── watchdog.py       # Probe deadlock and execution hang watchdog
│
├── learning/             # 🎓 Closed-loop feedback, threshold auto-tuning, and policy calibration
│   ├── config/           # Calibration hyperparameters and feature configurations
│   ├── models/           # Calibrated severity scoring models and feature weights
│   ├── repositories/     # Triage label and feedback persistence repositories
│   ├── baseline_tracker.py # Scan target baseline variance tracking
│   ├── feedback_loop.py  # Closed-loop triage signal and threshold adaptation
│   ├── finding_deduplicator.py # Semantic finding deduplication (TF-IDF/Cosine)
│   ├── nuclei_tag_optimizer.py # Dynamic Bayesian Beta-Binomial Nuclei template tag ranking
│   ├── policy_governance.py# Shadow evaluation, canary promotion, and atomic rollback gate
│   ├── threshold_tuner.py# PI-controller automatic threshold calibration
│   └── versioned_policy.py# Immutable VersionedPolicy container for priority queue tuning
│
├── mesh/                 # 🕸️ Actor Mesh interfaces and distributed state sharing
├── notifications/        # 📬 Notification routing, escalation policies, and digest grouping
│   ├── bridge.py         # Central event-driven notification bridge
│   ├── digest.py         # Digest aggregation and interval flush
│   ├── escalation.py     # Alert escalation matrices for Critical findings
│   ├── filters.py        # Severity, target, and compliance alert filtering
│   ├── inbox.py          # In-app notification center inbox
│   ├── routing.py        # Rule-based alert routing
│   └── snooze.py         # Temporary notification suppression and snooze policies
│
├── pipeline/             # 🔀 Distributed DAG Orchestrator and stage lifecycle
│   ├── constants/        # Pipeline stage names, exit codes, and status enums
│   ├── parallel_analysis/# Parallel stage execution coordination
│   ├── retry/            # Exponential backoff and Retry-After policy handlers
│   ├── self_healing/     # Dynamic failure recovery, stage skipping, and re-routing
│   ├── services/         # Orchestrator core services:
│   │   └── pipeline_orchestrator/ # DAG builder, actor scheduler, stage executors
│   │       ├── stage_admit.py     # authorize → consume (I28) → sandbox
│   │       ├── graph_builder.py   # `_BASE_NODES` + `_join_finding_producers`
│   │       └── _constants.py      # import-time STAGE_GRAPH / STAGE_TIMEOUTS (subset of runtime graph)
│   ├── authority_bootstrap.py # `attach_pipeline_authority` (fail-closed); HuntBudget/bandit/authorizer live here
│   ├── storage_tiering.py# Artifact retention: hot NVMe cache → gzip compressed archive & pruning
│   ├── output_history.py # Historical and active scan run search indexer
│   └── unified_cache/    # Integrated cross-stage result caching
│
├── realtime/             # 📡 Real-time telemetry, WebSocket hub, and PrioritizedRealtimeBroker (P0-P4 QoS)
│
├── recon/                # 🌐 Asset discovery and reconnaissance engines
│   ├── api_specs/        # OpenAPI/Swagger, WSDL, and GraphQL schema reconstructors
│   ├── cloud_recon/      # AWS S3, Azure Blob, GCP bucket, Firebase, Wasabi, OCI, and CloudFlare discoverers
│   ├── collectors/       # Passive OSINT collectors (AlienVault, Wayback, Sublist3r)
│   ├── graphql/          # GraphQL endpoint detection and introspection crawler
│   ├── js_parsers/       # JavaScript AST parser, secret extractor, and route finder
│   ├── live_hosts/       # Fast ICMP/TCP/HTTP port probing and service identification
│   └── sources/          # Domain, DNS, WHOIS, and certificate transparency sources
│
├── reporting/            # 📄 Multi-format vulnerability reporting and compliance
│   ├── platforms/        # Exporters for HackerOne, Bugcrowd, Intigriti, Synack, YesWeHack, Google VRP, MSRC, Meta, Apple, ServiceNow, DefectDojo, Jira
│   ├── compliance_attestation.py # SOC 2, ISO 27001, PCI-DSS compliance attestations
│   ├── compliance_mapping.py # Automated regulatory control mapping (SOC 2, ISO 27001, PCI-DSS, NIST 800-53)
│   ├── compliance_pdf.py # Cryptographically signed PDF report generator
│   ├── sarif_exporter.py # Validated SARIF 2.1.0 engine
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
4. **`src/output/` is gitignored**. Storage tiering and run history live under `src/pipeline/` (`storage_tiering.py`, `output_history.py`). Do not recreate a kernel / God-container. Keep `ValidatedPipelineConfig`, `DashboardConfig`, and `QueueConfig` separate.
5. **Do not merge** the duplicate `PluginRegistry` (`framework.py` vs `registry.py`) or the unused third EventBus (`src/core/events/bus.py`).
