# Documentation Index

Welcome to the Cyber Security Test Pipeline documentation portal. This hub indexes all architectural blueprints, developer guides, operations references, and API specifications.

---

## 🚀 Core Getting Started & Architecture

- **[🚀 Getting Started Guide](getting-started.md)**: Environment setup, dependency installation, scope configuration, and running your first scan.
- **[📂 Codebase Map](codebase.md)**: Exhaustive structural map covering all 35 modules in `src/`, plus `frontend/src/`, `tests/`, `configs/`, `deploy/`, and `scripts/`.
- **[🏗️ Architecture Overview](architecture-overview.md)**: Engineering-focused map of subsystems, data flows, and design patterns.
- **[🏛️ System Architecture Deep Dive](architecture.md)**: The 10 Laws of Distributed Correctness, 7-Layer Control Plane, Partitioned Single-Writer Authority, 5-Stage Claim Settlement, Out-of-Band Policy Governance, Prioritized QoS Telemetry, and Deterministic Replay.
- **[📄 ExecutionRequest Contract of Intent](architecture/execution-request-contract.md)**: Formal handoff protocol (`Decision` → `Authorization` → `Scheduling` → `Worker`), scope token verification, and stateless execution.
- **[⚡ Cache Unification Design](architecture/cache-unification.md)**: Single-flight coalesced multi-tiered caching architecture.

---

## 💻 Operations, CLI & Deployment

- **[📜 Commands Reference](commands.md)**: Comprehensive CLI reference for `cstp` (`scan`, `start`, `launch`, `system`, `plugin`), scripts, and Make targets.
- **[🌍 Environment Variables Reference](environment-variables.md)**: Exhaustive catalog of all environment variables across backend and frontend subsystems.
- **[🚢 Deployment & Infrastructure](deployment.md)**: Docker Compose, Kubernetes, and Terraform deployment patterns.
- **[🌐 Multi-Region Topology](multi-region.md)**: Cross-region sharding, latency mitigation, and Zero-Trust networks.
- **[🚀 CI/CD Integration Guide](ci-cd-integration.md)**: Automated security scanning in GitHub Actions/GitLab CI, exit codes, and SARIF 2.1.0 report generation.

---

## 🔍 Security, Analysis & Verification

- **[⚡ Performance Models & Benchmarks](performance.md)**: Vectorized SIMD processing, probabilistic Bloom filters, and resource budgets.
- **[🔌 Dynamic Plugin SDK](dynamic-plugins.md)**: Writing, testing, and sandboxing custom Python/WASM security check plugins.
- **[🧪 Testing & Quality Assurance](testing.md)**: Guide to pytest suites (unit, integration, architecture, regression) and frontend testing.
- **[🛠️ Troubleshooting & Decision Tree](troubleshooting.md)**: Diagnostic flowchart and error remediation procedures.
- **[⚠️ Failure Modes & Degraded Scans](FAILURE_MODES.md)**: Detailed taxonomy of scan failures, circuit breaker trips, and interpreting zero-finding results.
- **[📊 Observability & Metrics Catalog](OBSERVABILITY_CATALOG.md)**: Prometheus metrics, OpenTelemetry spans, structured JSON logging, and Grafana dashboard provisioning.
- **[📚 Glossary](glossary.md)**: Terminology definitions, stage enums, and scan profiles.

---

## 🎨 Frontend & UI Operations

- **[🎨 Frontend Handbook](frontend.md)**: React 19 architecture, Tailwind CSS 4, Zustand stores, WebSocket telemetry, and 3D Cockpit.
- **[📑 Frontend Pages Overview](frontend_pages_overview.md)**: Detailed screen-by-screen breakdown of all operator console views and routes.

---

## 🏛️ Standards & History

- **[🤝 Contributing Guidelines](../CONTRIBUTING.md)**: Code style, linting rules, and PR workflows.
- **[🔒 Security Policy](../SECURITY.md)**: Vulnerability disclosure policy and secret rotation practices.
- **[⏱️ Benchmark Records](../BENCHMARK.md)**: Performance benchmarks and SIMD execution timings.
- **[📜 Changelog](../CHANGES.md)**: Historical changelog of features, fixes, and refactoring waves.
