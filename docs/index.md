# Documentation Index

Welcome to the Cyber Security Test Pipeline documentation portal. Charts live in [flowchart.md](flowchart.md) (incremental edits only). When docs and code disagree, **code wins** unless the doc is the named contract and the code is the bug.

Live scan path is **FrontierWAL + SettlementCoordinator + scan EventBus** (F-004). Raft **PartitionWAL + FSM.Apply + DurableOutbox** is the authority plane (F-003), single-node quorum-1 on CLI. Do not unify the two logs.

---

## Core architecture

- **[Getting Started](getting-started.md)**: Install, first scan, exit codes, config trees.
- **[Codebase Map](codebase.md)**: `src/`, `frontend/src/`, `tests/`, `configs/`, `deploy/`, `scripts/`.
- **[System Architecture Specification](architecture.md)**: 10 axioms, 6-level hierarchy, I1–I29 plus I30–I37, dual-log honesty, operational lifecycles.
- **[Architecture Overview](architecture-overview.md)**: Subsystems and single source of authority.
- **[Flowchart Atlas](flowchart.md)**: Survivor charts F-001–F-033. No full rewrite.

---

## Operations, CLI & deployment

- **[Commands Reference](commands.md)**: `cstp` scan / launch / start / system / plugin.
- **[Environment Variables](environment-variables.md)**: `DASHBOARD_*`, `QUEUE_*`, signing keys, feature flags.
- **[Deployment](deployment.md)**: Compose, Kubernetes templates, signing-key restart rule.
- **[Multi-Region Topology](multi-region.md)**: I36 single-writer, I37 fence. Live CLI is `local`.
- **[CI/CD Integration](ci-cd-integration.md)**: Workflow `276806682`, shards, coverage 45%, exit codes.

---

## Security, analysis & verification

- **[Performance Models](performance.md)**: `qos_admit`, Bloom, budgets. Mesh times are models, not a running cluster.
- **[Dynamic Plugin SDK](dynamic-plugins.md)**: `cstp plugin new`; two PluginRegistry copies stay.
- **[Testing & QA](testing.md)**: Shards, 20s per-test timeout, local ≤50s rule.
- **[Troubleshooting](troubleshooting.md)**: Short index into FAILURE_MODES.
- **[Failure Modes](FAILURE_MODES.md)**: I34 table, I35 protocol, exit lattice.
- **[Observability Catalog](OBSERVABILITY_CATALOG.md)**: Prometheus series, alerts, Grafana.
- **[Glossary](glossary.md)**: I30–I37, leases, finding surface, dual WAL.

---

## Frontend

- **[Frontend Handbook](frontend.md)**: React 19, Zustand, normalizer, real SSE/WS paths.
- **[Frontend Pages Overview](frontend_pages_overview.md)**: Routes from `RouteConfig.tsx` only.

---

## Standards

- **[Security Policy](../SECURITY.md)**: Vulnerability disclosure.

`CONTRIBUTING.md`, `BENCHMARK.md`, and `CHANGES.md` are not in this repository. Do not link them.
