# Documentation Index

Welcome to the Cyber Security Test Pipeline documentation portal. This hub indexes all architectural blueprints, developer guides, operations references, and API specifications.

---

## 🚀 Core Getting Started & Architecture

- **[🚀 Getting Started Guide](getting-started.md)**: Environment setup, dependency installation, scope configuration, and running your first scan.
- **[📂 Codebase Map](codebase.md)**: Exhaustive structural map covering all 35 modules in `src/`, plus `frontend/src/`, `tests/`, `configs/`, `deploy/`, and `scripts/`.
- **[🏛️ System Architecture Specification & Engineering Contract](architecture.md)**: Unified master blueprint containing the 10 Non-Negotiable System Axioms, 6-Level Authority Hierarchy, I1–I29 plus cross-subsystem I30–I37, Raft consensus protocol, and operational lifecycles.
- **[📋 Formal Command & State Transition Specification](FORMAL_COMMAND_SPECIFICATION.md)**: Complete transition matrix, schemas, preconditions, budget equations, and recovery semantics for all system commands.
- **[🏗️ Architecture Overview](architecture-overview.md)**: Engineering-focused map of subsystems, data flows, and design patterns.
- **[🔀 Flowchart Atlas](flowchart.md)**: One mermaid file. Overlapping or nested flows are merged into survivor charts; retired ids stay as pointers. Incremental edits only — no full rewrite.
- **[🔍 Architecture Gap Analysis](GAP_ANALYSIS.md)**: Technical audit of open gaps, in-memory simulations, and roadmap alignment.
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
