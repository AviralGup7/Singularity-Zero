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
├── unit/                 # Domain-specific isolated unit tests
│   ├── analysis/         # Security analyzer and signal detection tests
│   ├── auth/             # Authentication, RBAC, and session lifecycle tests
│   ├── cli/              # Command line argument parser and rich UI tests
│   ├── core/             # Core contracts, utilities, and cryptographic vault tests
│   ├── dashboard/        # FastAPI endpoints and route handlers
│   ├── exploitation/     # Exploit engine payload generation and safety tests
│   ├── learning/         # ML model training, deduplication, and feedback tests
│   ├── pipeline/         # DAG graph builder, scheduler, and retry logic
│   └── recon/            # Recon collectors, DNS, and parsing tests
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

# Run integration tests
pytest tests/integration/

# Run Target Architecture Invariants Suite (All 16 Formal Invariants)
pytest tests/integration/test_target_architecture_invariants.py

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

---

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

   # Sync active schema to docs/api-reference.md
   python scripts/validate_openapi.py --write
   ```

5. **Secret Leakage Prevention (`scripts/verify_bundle_secrets.py`)**:
   Scans built distribution assets and commits for exposed API keys, private keys, and authorization tokens.
   ```bash
   python scripts/verify_bundle_secrets.py
   ```
