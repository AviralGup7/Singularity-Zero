# Documentation Index

Welcome to the Cyber Security Test Pipeline documentation. This index helps you navigate the technical guides and architectural overviews.

---

## 📖 Core Documentation

- **[🚀 Getting Started](getting-started.md)**: Environment setup, tool installation, and development workflow.
- **[🏗️ System Architecture & Lifecycle](architecture.md)**: Design principles, the orchestrator model, data flow, and stage lifecycle.
- **[📂 Codebase Map](codebase.md)**: Detailed package directory and module responsibilities.
- **[📜 Commands Reference](commands.md)**: Full CLI reference for development and production.
- **[🧪 Testing & CI](testing.md)**: How to run the unit, integration, and architecture test suites.
- **[🔍 Comprehensive Gap Analysis](GAP_ANALYSIS.md)**: Technical and architectural gaps roadmap.
- **[🚀 Evolution Alpha Plan](EVOLUTION_ALPHA_PLAN.md)**: Roadmap for major feature additions and improvements.
- **[🧬 Pipeline Orchestration Analysis](PIPELINE_ORCHESTRATION_ANALYSIS.md)**: 2026-Q2 conceptual audit of `src/pipeline/` — DAG execution, circuit-breaker wiring, retry granularity, parallelism strategy, caching, self-healing, maintenance, tools/capabilities, validation, visual testing, plan rigidity, checkpoint resume, event-driven control plane, CI/CD integration, and the local-vs-distributed gap.

---

## 🔍 Specialized Guides

- **[🎨 Frontend Handbook](frontend.md)**: Tech stack, routes, state management, and styling for the React dashboard.
- **[📚 Glossary](glossary.md)**: Definitions of core terms and scan modes.
- **[📚 API Reference](api-reference.md)**: OpenAPI 3.1.0 specification and AI metadata for autonomous agent orchestration.
- **[🔌 Dynamic Plugin SDK](dynamic-plugins.md)**: Hot-load third-party security checks from a single Python file.
- **[⚡ Performance Models & Benchmarks](performance.md)**: SIMD optimization, Actor migration, and hardware benchmarks.
- **[🚀 CI/CD Integration](ci-cd-integration.md)**: Exit-code taxonomy, `policy.toml` schema, SARIF output, incremental scans, and `INGRESS_POLICY_RESULT` events.
- **[🛠️ Troubleshooting Logic](troubleshooting.md)**: Parseable decision tree for identifying and resolving pipeline execution failures.
- **[👻 Ghost-Actor Mesh Recovery Evidence](ghost_actor_recovery_evidence.md)**: CRDT snapshots, WAL dual-commit, and compaction gating evidence.

---

## 🚀 Deployment & Operations

- **[🚢 Deployment & Infrastructure](deployment.md)**: Orchestration modes, environment configuration, and Singularity-Zero production setup.
- **[🌍 Multi-Region Active-Active Sharding](multi-region.md)**: Cross-region topology, sharding models, and Zero-Trust network policies.

---

## 🏛️ Archive

- **[📜 Changelog](../CHANGES.md)**: Comprehensive changelog of all changes.
- **[⏱️ Benchmarks](../BENCHMARK.md)**: Bloom filter profiling and performance measurements.
- **[🗄️ Historical Logs](archive/)**: Contains old autonomous wave logs and execution prompts.
- **[📜 Archive Changelog](archive/CHANGELOG.md)**: Consolidated log of historical improvements.

---

## 🤝 Contributing

We value concise, example-driven documentation.
1. Keep guides actionable with copy-pasteable commands.
2. Update the **Codebase Map** when adding new top-level modules.
3. Ensure CI passes before submitting documentation PRs.
