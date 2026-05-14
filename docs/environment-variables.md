# Environment Variables Reference

This document is the single source of truth for all environment variables used by the Cyber Security Test Pipeline.

---

## 🔧 Infrastructure & Connectivity

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_URL` | Yes | `redis://localhost:6379/0` | Connection string for the Redis backplane (queue, Pub/Sub, checkpoints). |
| `DATABASE_URL` | Yes | `sqlite:///./pipeline.db` | SQL connection string for persistence of findings and telemetry. |
| `HTTP_PROXY` | No | (None) | Proxy URL for outbound scanning requests (supports `http://` and `socks5://`). |

## 🚀 Orchestration & Mesh

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MESH_ID` | No | `default` | Namespace for Local-Mesh P2P discovery. Isolates different scan environments. |
| `WORKER_ID` | No | (UUID) | Unique identifier for a worker node. Generated automatically if omitted. |
| `WORKER_CONCURRENCY` | No | `10` | Maximum number of parallel tasks a single worker node will accept. |
| `QUEUE_NAME` | No | `security-pipeline` | The Redis queue name used for task distribution. |
| `MDNS_PORT` | No | `8008` | The port used by workers for mDNS peer discovery and health API. |

## 📊 Performance & Safety

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_LEVEL` | No | `INFO` | Logging verbosity. One of: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `MAX_SCAN_DURATION` | No | `86400` | Global timeout in seconds (default 24h). Safety killswitch for runaway scans. |
| `SCAN_THREADS` | No | `50` | Default thread pool size for network-intensive IO operations. |

## 🔐 Security & Auth

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APP_SECRET_KEY` | Yes (Prod) | (None) | Secret key for JWT signing and CSRF protection. |
| `DASHBOARD_API_KEY` | No | (None) | static API key for administrative access to the dashboard. |
| `TRUSTED_PROXIES` | No | `127.0.0.1` | Comma-separated list of IP addresses allowed in `X-Forwarded-For`. |
