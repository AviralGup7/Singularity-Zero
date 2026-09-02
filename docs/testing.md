# Testing & Quality Assurance Guide

This document outlines the testing strategy, test suite organization, quality gates, and local verification workflows for the Cyber Security Test Pipeline.

---

## 🎯 Testing Philosophy & Taxonomy

1. **Fast, Isolated Unit Tests (`tests/unit/`)**: Verify discrete functions, classes, parsers, and contracts without external network access or subprocess execution.
2. **Integration Tests (`tests/integration/`)**: Validate multi-component interactions with in-memory/test-double databases, Redis queues, and HTTP mock handlers.
3. **Architecture Boundary Tests (`tests/architecture/`)**: Enforce modular separation, forbidden imports, and clean dependency layering across domain packages.
4. **Regression Tests (`tests/regression/`)**: Validate fixes for previously identified bugs, schema transitions, and edge cases.
5. **Frontend Test Suites (`frontend/`)**: Component unit and integration tests using Vitest, React Testing Library, and end-to-end browser assertions with Playwright.

---

## 📂 Test Directory Organization

```text
tests/
├── unit/                 # Domain-specific isolated unit tests across 31 module subdirectories
│   ├── analysis/         # Security analyzer and signal detection tests
│   ├── api_tests/        # API route and client tests
│   ├── auth/             # Authentication, RBAC, and session lifecycle tests
│   ├── bootstrap/        # Authority bootstrapping and context creation tests
│   ├── config/           # Configuration schema validation tests
│   ├── console/          # Operator console and layout tests
│   ├── core/             # Core contracts, utilities, and cryptographic vault tests
│   ├── dashboard/        # FastAPI endpoints and route handlers
│   ├── decision/         # Bayesian bandit, priority queue, and authorizer tests
│   ├── detection/        # Vulnerability detection heuristics
│   ├── execution/        # Execution workers and runtime sandboxing tests
│   ├── exploitation/     # Exploit engine payload generation and safety tests
│   ├── frontier/         # Replicated log, state authority, and WAL recovery tests
│   ├── fuzzing/          # Active fuzzing orchestrator tests
│   ├── infrastructure/   # Flow control, PID, circuit breaker, and DB metrics tests
│   ├── intel/            # Threat intel heuristics and voting tests
│   ├── intelligence/     # Graph reasoning and CVE aggregation tests
│   ├── jobs/             # Job state machine and execution lifecycle tests
│   ├── learning/         # ML policy governance, deduplication, and feedback tests
│   ├── mesh/             # P2P gossip encryption, fragmentation, and sync tests
│   ├── notifications/    # Slack, Discord, and webhook dispatcher tests
│   ├── pipeline/         # DAG graph builder, scheduler, and retry logic
│   ├── realtime/         # Prioritized QoS broker and lane shedding tests
│   ├── recon/            # Recon collectors, DNS, and parsing tests
│   ├── reporting/        # Platform clients (Jira, ServiceNow, DefectDojo) and export tests
│   ├── resilience/       # Adaptive rate limiters and recovery tests
│   ├── sandbox/          # Process isolation, seccomp filters, and egress guard tests
│   ├── scripts/          # Operational script tests
│   ├── websocket_server/ # WebSocket protocol, broadcaster, and metrics tests
│   └── test_*.py         # Cross-cutting invariant, authority, and CLI launch tests
│
├── integration/          # Multi-component integration tests (Redis, DB, Orchestrator)
├── architecture/         # Layer boundary and import linter architecture assertions
└── regression/           # Fixed bug regression and contract attestation tests
```

---

## 🚀 Running Tests Locally

### 1. Run Python Backend Tests
```bash
# Run all unit tests
pytest tests/unit/

# Run architecture boundary validation
pytest tests/architecture/

# Run Integration Tests
pytest tests/integration/

# Run 34-Point Hardened Authority & Invariant Test Suites
pytest tests/unit/test_hardened_authority_invariants.py tests/unit/test_formal_invariants.py tests/unit/test_distributed_invariants.py tests/integration/test_target_architecture_invariants.py tests/unit/decision/test_architectural_invariants.py

# Run Deterministic Replay & Schema Upcasting Suite
pytest tests/integration/test_deterministic_replay.py

# Run regression test suite
pytest tests/regression/

# Run full test suite with coverage report
pytest --cov=src --cov-report=term-missing
```

### 2. Run Frontend Tests
```bash
cd frontend

# Run Vitest component tests
npm run test

# Run frontend lint and type-checks
npm run lint
npx tsc --noEmit
```

---

## 🏛️ Architecture Boundary Assertions

Boundary assertions in `tests/architecture/` strictly enforce dependency hierarchy:
- `core` cannot import from `pipeline`, `analysis`, or `dashboard`.
- `recon` cannot import from `dashboard` or `reporting`.
- `analysis` cannot import directly from `reporting`.
- All inter-stage communication must pass through typed `StageInput` and `StageOutput` contracts.

---

## 🔒 Hermetic Mocking & Testing Policies

- **Subprocess Mocking**: External CLI tools (`subfinder`, `httpx`, `nuclei`, `katana`) must never be invoked directly during unit tests. Use `monkeypatch.setattr(subprocess, "run", fake_run)` or adapter mocking fixtures.
- **Network Call Isolation**: Use `httpx_mock` or `responses` fixtures to intercept outbound HTTP calls and provide deterministic test fixtures.
- **Filesystem Isolation**: Use `tmp_path` fixture for all tests that read or write file artifacts.
- **Optional Dependency Skipping**: Test modules exercising non-core optional dependencies (`hypothesis`, `aiohttp`, `bs4`, `python-multipart`, `defusedxml`) must guard execution with `pytest.importorskip("<pkg>")` to ensure clean test suite execution across lightweight local agent and container environments.
- **Static AST vs Dynamic Security Hardening**: Static AST tests (e.g. `test_security_hardening.py`) verify the absolute exclusion of insecure standard library parsers (such as raw `xml.etree.ElementTree`) from production code. Dynamic tests verify active mitigation behavior and skip if the test double parser is absent.

---

## GitHub Actions (workflow id `276806682`)

`.github/workflows/ci.yml` on `main`:

| Job | What |
|---|---|
| `lint` | ruff + format + Bandit HIGH (no continue-on-error) + detect-secrets |
| `mypy` | `mypy .` |
| `typescript` | `tsc --noEmit` (root `files: []` is empty on purpose) |
| `frontend` | eslint + production build / gzip budgets |
| `test / ${shard}` | `unit-infra`, `unit-core`, `unit-pipeline`, `unit-recon`, `unit-analysis`, `unit-dashboard`, `unit-exploit`, `unit-app`, `suites` |
| `coverage` | combine shards; `[tool.coverage.report] fail_under = 45` (hard). Per-shard `--cov-fail-under=0` |
| `security-audit` | dependency / advisory audit |
| `security-scan` | Semgrep `config: p/ci` (no `auditOn: push`) |
| `hardening` | repo hardening checks |
| `iac-scan` | Checkov 3.2.266, `framework: yaml`, `soft_fail: false` |
| `CI passed` | needs every job above; `fail-fast: false` on the test matrix |

Per-test timeout: `pytest-timeout>=2.4.0`; CI `PYTEST_ADDOPTS --timeout=20 --timeout-method=signal`. `[tool.pytest.ini_options] timeout = 20`, `timeout_method = "thread"`. Job-level 12 minutes.

**Local agents:** only the smallest relevant slice, ≤ ~50 seconds. Full suite belongs remotely. Fail-fast recon tests stay skipped. Do not CI-fail on `REPLACE_WITH_*` in `deploy/kubernetes/secrets.yaml`. Do not flip coverage/Bandit/Semgrep/Checkov back to soft-fail.

I30–I37 and live-path suites (run a slice, not the world):

```bash
pytest tests/unit/core/test_global_invariants.py tests/unit/core/test_invariant_graph.py \
       tests/unit/core/test_atlas_holes.py tests/unit/jobs/test_status.py \
       tests/unit/core/test_authority_transfer.py tests/unit/core/test_recovery_protocol.py
```

## 🛡️ Automated CI/CD Quality Gates (`scripts/`)

The repository enforces automated quality gates in CI/CD pipelines to prevent supply-chain drift, secret leakage, and schema regressions:

1. **Dependency Pinning (`scripts/verify_dependency_pins.py`)**:
   Verifies that dependencies in `pyproject.toml` use strict version pinning (`==`), preventing unverified upstream package updates.
   ```bash
   python scripts/verify_dependency_pins.py
   ```

2. **SBOM Baseline Drift Check (`scripts/validate_sbom.py`)**:
   Compares the current CycloneDX SBOM against `configs/sbom-baseline.json`.
   ```bash
   python scripts/validate_sbom.py
   ```

3. **Accessibility Audit (`scripts/verify_a11y.py`)**:
   Validates frontend templates for WCAG 2.2 AA accessibility and ARIA attribute compliance.
   ```bash
   python scripts/verify_a11y.py
   ```

4. **OpenAPI Schema Contract Check (`scripts/validate_openapi.py`)**:
   Audits FastAPI endpoints against `configs/openapi-baseline.json` to prevent API contract breaking changes.
   ```bash
   # Verify contract integrity
   python scripts/validate_openapi.py
   ```

5. **Secret Leakage Prevention (`scripts/verify_bundle_secrets.py`)**:
   Scans built distribution assets and commits for exposed API keys, private keys, and authorization tokens.
   ```bash
   python scripts/verify_bundle_secrets.py
   ```
