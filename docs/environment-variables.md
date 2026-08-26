# Environment Variables Reference

This document serves as the authoritative single source of truth for all environment variables supported by the Cyber Security Test Pipeline across backend services, distributed workers, threat intelligence integrations, and frontend components.

---

## 🏛️ Core Platform & Infrastructure

| Variable | Type | Default | Description |
|---|---|---|---|
| `APP_ENV` | string | `development` | Runtime environment (`development`, `staging`, `production`). |
| `APP_SECRET_KEY` | string | (None) | Secret key used for signing JWT authentication tokens and session cookies. |
| `DATABASE_URL` | string | `sqlite:///./data/pipeline.db` | SQLAlchemy database URL for persisting jobs, findings, and target metadata. |
| `REDIS_URL` | string | `redis://localhost:6379/0` | Connection URL for Redis (used for queue, pub/sub, Bloom mesh, and session caching). |
| `REDIS_PASSWORD` | string | (None) | Password for authenticated Redis connections. |
| `REDIS_TLS_CA_CERTS` | string | (None) | Path to CA bundle file for Redis mTLS connections. |
| `SEC_ENCRYPTION_KEY` | string | (None) | Master 256-bit AES encryption key for securing cached secrets and credentials. |
| `SEC_API_KEY_PEPPER` | string | (None) | Cryptographic pepper for Argon2id hashing of API keys. |
| `AUTHORITY_SIGNING_KEY` | string | (None) | HMAC-SHA256 key for command receipts (I13) and settlement/ticket HMAC. Falls back to `APP_SECRET_KEY`. If **neither** is set, a process-local random key is used — in-process verify works; **verify dies across restart**. No published fallback string. |
| `AUTHORITY_SIGNING_KEY_ID` | string | `authority-hmac-v1` | Key identifier string bound into certified command receipts. |
| `PIPELINE_GLOBAL_BUDGET_UNITS` | integer | `10000` | Total units allocated to `GlobalBudgetAggregate` (P-0000) for sub-lease distribution. |
| `FEATURE_WASM_PLUGINS` | boolean | `false` | Enable wasmtime AEVE sandbox. Default is `_MockWasmtime`. |
| `FEATURE_PPO` | boolean | `false` | Enable PPO evasion (`src/learning/rl.py`). Off = stub. |
| `ENABLE_THRESHOLD_TUNING` | boolean | unset | Opt-in threshold tuner. `true\|1\|yes` enables; `false\|0\|no` overrides config `enabled=True`. Default config `enabled=False`. |
| `STAGE_CAS_SOFT` | boolean | unset | Test hook: stage CAS keep-and-log instead of raising `IllegalStageTransitionError`. |

---

## 🌐 Server & Dashboard API (`src/dashboard/fastapi/config.py`)

All FastAPI server settings accept the `DASHBOARD_` environment variable prefix:

| Variable | Type | Default | Description |
|---|---|---|---|
| `DASHBOARD_HOST` | string | `127.0.0.1` | Network interface for the FastAPI REST server. |
| `DASHBOARD_PORT` | integer | `8000` | Port for the FastAPI REST service. |
| `DASHBOARD_WORKERS` | integer | `1` | Number of Uvicorn worker processes. |
| `DASHBOARD_DEBUG` | boolean | `false` | Enable debug logging and stack traces in API errors. |
| `DASHBOARD_ALLOWED_ORIGINS` | string | (empty) | Comma-separated list of allowed CORS origins. |
| `DASHBOARD_API_KEY` | string | (None) | Master API key for administrative API authentication. |
| `DASHBOARD_GUEST_ACCESS_ENABLED` | boolean | `false` | Allow unauthenticated read-only guest access. Local `create_app` setdefaults `true` when `APP_ENV` is not production/staging. |
| `DASHBOARD_AUTH_DISABLED` | boolean | `false` | Disable dashboard auth (grants admin). Local demo setdefaults `true` if unset. Origin validation still runs **before** this bypass. Guest-token tests must `monkeypatch.setenv("DASHBOARD_AUTH_DISABLED", "false")`. |
| `DASHBOARD_RATE_LIMIT_DEFAULT` | integer | `60` | Default rate limit (requests per minute per IP). |
| `DASHBOARD_RATE_LIMIT_JOBS` | integer | `10` | Rate limit for scan job creation endpoints. |
| `DASHBOARD_RATE_LIMIT_REPLAY` | integer | `30` | Rate limit for HTTP request replay endpoints. |
| `DASHBOARD_RATE_LIMIT_REMEDIATION` | integer | `5` | Rate limit for remediation trigger endpoints. |
| `DASHBOARD_REDIS_URL` | string | (None) | Optional Redis URL for distributed dashboard session/state caching. |
| `DASHBOARD_MTLS_ENABLED` | boolean | `false` | Enable mutual TLS verification for incoming REST connections. |

---

## 🔌 Real-Time WebSocket Server (`src/websocket_server/`)

| Variable | Type | Default | Description |
|---|---|---|---|
| `WS_ALLOWED_ORIGINS` | string | `*` | Allowed origins for incoming WebSocket connections. |
| `WS_JWT_SECRET` | string | (None) | Secret key for authenticating WebSocket token handshakes. |
| `WS_HEARTBEAT_INTERVAL` | integer | `30` | Interval in seconds between WebSocket ping frames. |
| `WS_HEARTBEAT_TIMEOUT` | integer | `10` | Timeout in seconds before terminating non-responsive connections. |
| `WS_MAX_CONNECTIONS_PER_IP` | integer | `20` | Concurrent WebSocket connection limit per IP address. |
| `WS_MAX_MESSAGE_SIZE` | integer | `1048576` | Maximum allowed WebSocket message frame size in bytes (1MB). |
| `WS_RATE_LIMIT_CAPACITY` | integer | `100` | Token bucket capacity for inbound WebSocket control messages. |

---

## 🕸️ Distributed Actor Mesh & Sharding (`src/infrastructure/mesh/`)

| Variable | Type | Default | Description |
|---|---|---|---|
| `MESH_SECRET` | string | (None) | Shared HMAC secret for authenticating SWIM gossip packets. |
| `MESH_BIND_INTERFACE` | string | (None) | Interface name or IP address for binding the P2P mesh listener. |
| `MESH_REGION` | string | `local` | Geographic region tag (e.g. `us-east-1`, `eu-west-1`) for latency-aware routing. |
| `MESH_ZONE` | string | `default` | Availability zone tag for fault-domain isolation. |
| `MESH_LEADER_ELECTION_TIMEOUT_SEC` | float | `10.0` | Leader election consensus timeout in seconds. |
| `MESH_LEADER_LEASE_TTL_MS` | integer | `15000` | Redis leader lease time-to-live in milliseconds. |
| `MESH_LEADER_REFRESH_SEC` | float | `5.0` | Leader lease refresh heartbeat interval in seconds. |
| `MESH_PEER_RATE_LIMIT_PPS` | integer | `200` | Maximum gossip packets per second per peer node. |
| `MESH_FRAGMENT_THRESHOLD` | integer | `1300` | Safe UDP MTU threshold before fragmenting mesh packets. |

---

## 📊 Observability, Metrics & Tracing (`src/infrastructure/observability/`)

| Variable | Type | Default | Description |
|---|---|---|---|
| `OBSERVABILITY_METRICS_ENABLED` | boolean | `true` | Enables Prometheus metrics collection and `/metrics` endpoint. |
| `OBSERVABILITY_METRICS_PORT` | integer | `9090` | Dedicated metrics port when running in standalone sidecar mode. |
| `OBSERVABILITY_TRACING_ENABLED` | boolean | `true` | Enables OpenTelemetry distributed tracing spans. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | string | `http://localhost:4317` | OpenTelemetry OTLP collector gRPC endpoint. |
| `OBSERVABILITY_LOG_LEVEL` | string | `INFO` | Structured logging minimum level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `OBSERVABILITY_LOG_FORMAT` | string | `json` | Log output format (`json` for machine ingestion or `console` for human readability). |

---

## 🕵️ Threat Intelligence API Keys

Live HTTP clients live in `src/intelligence/feeds/`. `src/intel/` is an offline console vote store that only *checks* whether keys are set.

| Variable | Type | Description |
|---|---|---|
| `SHODAN_API_KEY` | string | API key for Shodan host discovery and open port enumeration. |
| `VT_API_KEY` | string | **Canonical** VirusTotal API key (recon + threat intel). |
| `VIRUSTOTAL_API_KEY` | string | Deprecated alias; used only if `VT_API_KEY` is unset. |
| `PIPELINE_OFFLINE` | boolean | When `1`/`true`, skip NVD/MITRE/EPSS/KEV network enrichment. |
| `OTX_API_KEY` | string | AlienVault Open Threat Exchange (OTX) API key for passive IOC feeds. |
| `SECURITYTRAILS_API_KEY` | string | API key for SecurityTrails historical DNS and subdomain records. |
| `LEAKIX_API_KEY` | string | API key for LeakIX exposed service and leak searches. |
| `MISP_URL` | string | Base URL of your private or community MISP instance. |
| `MISP_API_KEY` | string | API key for querying MISP threat attributes and campaigns. |

---

## 🎯 Bug Bounty Platform Integrations (`src/analysis/bug_bounty/`, `src/reporting/platforms/`)

| Variable | Type | Description |
|---|---|---|
| `HACKERONE_API_TOKEN` | string | HackerOne API token for automated scope sync and report drafting. |
| `HACKERONE_PROGRAM_HANDLE` | string | HackerOne program handle identifier. |
| `BUGCROWD_API_TOKEN` | string | Bugcrowd API token for program scope sync. |
| `INTIGRITI_API_TOKEN` | string | Intigriti API token for scope synchronization. |
| `YESWEHACK_API_TOKEN` | string | YesWeHack API token for scope retrieval and finding submission. |

---

## 🚦 CI/CD & Branch Governance

| Variable | Description |
|---|---|
| `CYBER_BRANCH` | Explicit branch name override for `[on_findings] branch_glob` compliance matching. |
| `GITHUB_REF_NAME` | Automatically detected on GitHub Actions runners. |
| `CI_COMMIT_REF_NAME` | Automatically detected on GitLab CI runners. |
| `BRANCH_NAME` | Standard CI environment branch variable (Jenkins / Azure Pipelines). |
