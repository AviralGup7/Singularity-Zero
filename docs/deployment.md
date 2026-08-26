# Deployment & Infrastructure

This page maps the files that actually exist under `deploy/` and the compose files at the repo root. It is not a multi-host cluster runbook. Live CLI remains single-node quorum-1.

## Docker Compose

```bash
# Full-stack local (API, Redis, optional Grafana/Prometheus)
docker compose up --build

# Production-oriented composition
docker compose -f docker-compose.optimized.yml up --build -d
```

Bind services to `0.0.0.0` in containers. Dashboard: `cstp start dashboard --host 0.0.0.0 --port 8000`. Worker: `cstp start worker`.

## Kubernetes (`deploy/kubernetes/`)

| File | Role |
|---|---|
| `namespace.yaml` | Namespace |
| `configmap.yaml` | Non-secret config |
| `secrets.yaml` | **Undeployable template** — values are `REPLACE_WITH_*` on purpose. Do not treat that string as a CI failure. |
| `dashboard.yaml` | API deployment |
| `worker.yaml` | Worker deployment |
| `redis.yaml` | Redis |
| `ingress.yaml` | Ingress |

Intentional leftovers: PVC is RWO with replicas=1; worker NetworkPolicy allows 80/443 egress.

## Terraform (`deploy/terraform/`)

Cloud scaffolding only. It does not stand up a Raft cluster. `NetworkRaftTransport` stays LIBRARY.

## Prometheus

`deploy/prometheus-docker.yml` plus Grafana dashboards described in [OBSERVABILITY_CATALOG.md](OBSERVABILITY_CATALOG.md).

## Secrets and signing

Set these in the real environment, not in git:

- `APP_SECRET_KEY`
- `AUTHORITY_SIGNING_KEY` (and optional `AUTHORITY_SIGNING_KEY_ID`)
- `DASHBOARD_API_KEY` / `DASHBOARD_AUTH_DISABLED=false` in production
- `MESH_SECRET` if gossip is enabled
- `REDIS_URL` / `DATABASE_URL`

If `AUTHORITY_SIGNING_KEY` and `APP_SECRET_KEY` are both unset, receipt and ticket HMAC uses a **process-local** `secrets.token_bytes(32)` / `token_hex(32)`. In-process verify works; **verify dies across restart**. There is no published fallback string.

## Multi-region

Read [multi-region.md](multi-region.md). I36/I37 name the consistency model. `initiate_transfer` is called from tests, not from the live scan path. Do not invent a second writer.
