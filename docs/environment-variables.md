# Environment Variables Reference

This document serves as the single source of truth for all environment variables supported by the Cyber Security Test Pipeline.

---

## 🔧 Infrastructure & Connectivity

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_URL` | Yes | `redis://localhost:6379/0` | Connection string for the Redis backplane (queue, Pub/Sub, checkpoints). |
| `REDIS_PASSWORD` | No | (None) | Password for Redis authentication in production. |
| `DATABASE_URL` | Yes | `sqlite:///./data/pipeline.db` | SQLite connection string for persistent storage of scan runs and findings. |
| `HTTP_PROXY` | No | (None) | Outbound HTTP/SOCKS5 proxy URL for scanner requests. |
| `MESH_SECRET` | Yes (Mesh Mode) | (None) | Mandatory shared HMAC secret for authenticating the Gossip protocol. |
| `MESH_BIND_INTERFACE` | No | (None) | Restricts the Gossip UDP server to bind only to a specific network interface. |

---

## 🚀 Server & Dashboard Configurations

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HOST` | No | `127.0.0.1` | Binding interface for the FastAPI server. |
| `PORT` | No | `8000` | Port for the FastAPI dashboard service. |
| `WORKERS` | No | `1` | Number of concurrent dashboard server workers. |
| `CORS_ORIGINS` | No | `http://localhost:3000,http://localhost:5173` | Allowed origins for cross-origin UI requests. |
| `DASHBOARD_RATE_LIMIT_JOBS` | No | `10` | Rate limit for starting scan jobs (requests per minute). |
| `DASHBOARD_RATE_LIMIT_REPLAY` | No | `30` | Rate limit for replay endpoints (requests per minute). |
| `DASHBOARD_RATE_LIMIT_REMEDIATION` | No | `5` | Rate limit for remediation verification endpoints (requests per minute). |
| `DASHBOARD_RATE_LIMIT_DEFAULT` | No | `60` | Default API rate limit for miscellaneous endpoints (requests per minute). |

Any field on the `DashboardConfig` schema can also be explicitly overridden using the `DASHBOARD_` prefix (e.g. `DASHBOARD_PORT`).

---

## 📦 Queue & Distributed Workers

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WORKER_CONCURRENCY` | No | `4` | Maximum parallel job slots allowed per worker node. |
| `WORKER_MAX_JOBS` | No | `1000` | Limits total jobs before auto-restarting the worker. |
| `WORKER_QUEUE` | No | `security-pipeline` | Target Redis queue name for task distribution. |

---

## 📊 Performance & Limits

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CACHE_TTL` | No | `3600` | Cache time-to-live in seconds. |
| `CACHE_BACKEND` | No | `redis` | Cache storage backend driver (`redis` or `memory`). |
| `RATE_LIMIT_RPS` | No | `10` | Default rate limit per target in requests per second. |
| `RATE_LIMIT_GLOBAL_RPS` | No | `30` | Shared global rate limit cap across all tasks. |
| `MAX_CONCURRENT_SCANS` | No | `5` | Maximum scans allowed to run concurrently. |

---

## 🔐 Security & Auth

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_SECRET_KEY` | Yes (Prod) | (None) | Secret key for signing sessions and JWT tokens. |
| `APP_ENV` | No | `development` | Deployment environment context (`development` or `production`). |
| `ENABLE_API_SECURITY` | No | `false` | Enables auth token checks globally on dashboard API. |
| `ALLOWED_NETWORKS` | No | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Permitted IP subnets for scan scopes (private network validation). |
| `NUCLEI_SIGNATURE_PUBLIC_KEY` | No | `8c6f1406e2cf6fb4ef1e97d191d8481dfb152d1136c1e550e6ee693b7df0898c` | Ed25519 public key hex string used to verify template manifest signature. |
| `NUCLEI_MANIFEST_DIR` | No | `configs/templates` | Directory containing `manifest.json` and `manifest.json.sig` for template integrity check. |

---

## 📡 HTTP Request Headers & Context Variables

In addition to system configurations, the system ingests custom HTTP request headers to govern multi-tenancy and security boundaries. 

> **SOURCE OF TRUTH**: For detailed header requirements, dynamic namespacing scopes, and anti-CSRF policies, see [API Reference - Global Security Headers](api-reference.md#global-security-governance-headers).

| Header | Required | Default | Description |
|--------|----------|---------|-------------|
| `X-Tenant-ID` | No | `default` | Identifies client tenant context. See [Global Security Headers](api-reference.md#global-security-governance-headers). |
| `X-CSRF-Token` | Yes (Mutating requests) | (None) | Stateless double-submit cookie token. See [Global Security Headers](api-reference.md#global-security-governance-headers). |

---

## 🧠 Feature Flags

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENABLE_EXPLOITATION` | No | `false` | Master switch for auto-exploitation stages. |
| `ENABLE_LEARNING` | No | `true` | Enables AI active learning loop feedback integration. |
| `ENABLE_NOTIFICATIONS` | No | `false` | Enables third-party integration alerts. |
| `ENABLE_THREAT_INTEL` | No | `false` | Enables external threat intelligence feed lookup. |
