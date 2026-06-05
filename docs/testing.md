# Testing and CI

This document summarizes how to run tests locally and recommendations for CI.

## Testing Strategy Philosophy

Testing should provide fast, reliable feedback to developers and CI. Favor many small, deterministic unit tests for core logic, use integration tests to validate interactions between components, add regression tests for confirmed bug fixes, and reserve end-to-end (e2e) tests for critical user or pipeline flows. Keep e2e tests narrow to reduce flakiness. Tests should be deterministic, isolated, and easy to run locally.

## What Belongs Where

- **Unit tests**: fast, isolated tests that exercise a single function or class. No network, no real binaries. Place these under `tests/unit/`, organized by domain (`tests/unit/core/`, `tests/unit/analysis/`, `tests/unit/pipeline/`, `tests/unit/recon/`, `tests/unit/dashboard/`, `tests/unit/execution/`, `tests/unit/api_tests/`, `tests/unit/reporting/`). New modules must include unit tests.
- **Integration tests**: verify interactions between multiple components (DB, HTTP clients, queues, filesystem). These may use real services (docker, test containers) or well-structured test doubles. Place under `tests/integration/`.
- **Regression tests**: small tests added to capture a previously-observed bug and prevent re-introduction. Put these in `tests/regression/` or next to the unit test that demonstrates the bug (name clearly to indicate the bug ID or root cause).
- **End-to-end (e2e) tests**: full-system workflows that exercise user-facing or pipeline flows. These are slower and more brittle; tag with `@pytest.mark.e2e` and run them in gated CI stages or on demand. Place under `tests/e2e/`.

## Regression and Fallback Testing

To guarantee the high-availability of machine learning classifiers, priority queues, and distributed clocks under extreme operational limits, the following suites are enforced:
- **ML Fallback Regression Suite** (`tests/regression/test_ml_regression.py`): Automates regression validation on the historical golden set (`tests/fixtures/ml_golden_set.json`), ensuring that the pure-NumPy logistic regression fallback deviates by less than `0.15` MSE from the fitted pipeline. It also validates that the pure-NumPy matrix math has exactly `0.000000` MSE deviation from a standard scikit-learn `LogisticRegression` classifier under identical weights.
- **Priority Queue Aging and Decay Suite** (`tests/unit/test_priority_queue_decay.py`): Validates that the priority queue's dynamic `effective_priority` enforces the 120-second boost decay half-life and wait-time aging bonuses, checking that max-heap ordering is completely correct and starvation-safe under popped and peeked lifecycles.
- **Hybrid Logical Clocks Causality Suite** (`tests/unit/core/frontier/test_hlc.py`): Validates the constant-size $O(1)$ causal ordering and convergent merges of the `HybridLogicalClock` implementation. Tests ticking, physical drift thresholds, logical increment counters, and `LWWset.merge` tie-breaking.

---

## 🌀 Multi-Node Stress & Chaos Engineering Suites

To validate mesh resilience, dynamic failover, and crash tolerance under production-grade hardware stress and service outages, two dedicated test suites are integrated:

### 1. Multi-Node Stress Suite (`tests/stress/test_mesh_failover.py`)
This suite validates the scalability, actor lifecycle, and CRDT convergence of the custom asyncio-based Ghost-Actor Mesh under extreme load.
*   **Mailbox Concurrency Stress**: Floods the custom asyncio-based actor queue with 100+ concurrent state merge operations using un-blocked asynchronous futures to assert mailbox queue thread safety and prevent lock contention.
*   **Actor Migration Failover**: Simulates abrupt actor coordinator node deaths, asserting that active actors successfully serialize, migrate, and re-hydrate on cold nodes without state loss.
*   **Network Partition Split**: Artificially divides mesh participants and verifies that their discrete LWW-Sets converge conflict-free using CRDT Jaccard similarity once connection heals.
*   **WAL Dual-Commit Recovery**: Interrupts Redis connection while committing deltas, verifying that state events successfully fall back to the local append-only file (AOF) and resume streaming once Redis is reachable.

### 2. Chaos Engineering Suite (`tests/chaos/`)
Decorated with `@pytest.mark.chaos`, these tests simulate runtime hardware, link, and resource failures:
*   **Redis Failover & Circuit Breaker (`test_redis_failover.py`)**: Drops the primary Redis stream link mid-scan. Verifies that the Circuit Breaker trips to `OPEN`, immediately falls back to writing exclusively to the local AOF ledger without thread timeouts, and successfully replays/synchronizes when the connection is restored and the breaker heals.
*   **Mid-Migration Crash (`test_node_crash_during_migration.py`)**: Kills the source coordinator node precisely mid-migration to assert that the destination registry safely recovers from half-migrated actor envelopes with zero duplicate registrations.
*   **Network Split & CRDT Healing (`test_network_split.py`)**: Simulates a split-brain condition where nodes are partitioned, validating that the HLC-enforced clocks determine the correct causal history during automatic recovery.
*   **Disk Full Resilience (`test_disk_full.py`)**: Artificially injects an `ENOSPC` (No space left on device) or `OSError` failure during local WAL AOF disk flushes. Asserts that the system maintains scanning integrity by running durably on Redis Streams commits alone.

> [!NOTE]
> **Performance Metric Thresholds**: The simulated failure states, self-healing thresholds, and adaptive auto-scaling triggers in these chaos test suites match the active limits defined in [Performance - Bottleneck Detection & Mesh Auto-Scaling](performance.md#bottleneck-detection-mesh-auto-scaling).

### 3. Custom Actor & Subsystem Upgrades Suite (`tests/test_ghost_actor.py` & `tests/test_recovery_subsystem_upgrades.py`)
Validates actor state serializability with MessagePack and Zstd compression, recovery and rehydration from differential checkpoints, automatic AIMD compaction budgeting, and memory-safe credentials copying.

To run these advanced suites:
```bash
# Run the custom actor unit & recovery upgrades tests
pytest -v tests/test_ghost_actor.py tests/test_recovery_subsystem_upgrades.py

# Run the HLC causality tests
pytest -v tests/unit/core/frontier/test_hlc.py

# Run the multi-node stress suite
pytest -v tests/stress/test_mesh_failover.py

# Run the chaos engineering suite
pytest -v tests/chaos/
```


## Architecture Boundary Tests

- Architecture dependency rules are enforced in `tests/architecture/` and should run in CI.
- Explicit forbidden-import rules are validated by `tests/architecture/test_dependency_boundaries_enforced.py`.
- Current enforced rules include:
	- `core` must not import `pipeline`
	- `recon` must not import `dashboard`
	- `analysis` must not import `reporting`

## Fixture Architecture

- Use `tests/conftest.py` for shared project fixtures and scoped `conftest.py` files for package-specific setup.
- Prefer function-scoped fixtures for isolation; use `module` or `session` scope only for expensive resources that are safe to share.
- Keep fixtures small, single-purpose, and composable. Avoid hidden global state and ensure clear teardown.
- Document each important fixture in `tests/conftest.py` (docstring) describing scope, side effects, and common usage patterns.

## Important Fixtures and When To Use Them

- **`tmp_path` / `tmpdir`**: filesystem isolation for tests that read/write files.
- **`monkeypatch`**: patch env vars, attributes, or functions at test time.
- **`config_file` / `sample_config`**: temporary copies of `config.json` used by pipeline components.
- **`cli_runner` / `runner`**: invoke CLI entrypoints without spawning real subprocesses.
- **`httpx_mock` / `responses`**: mock outbound HTTP requests and assert requests/responses.
- **`db_session` / `in_memory_db`**: database fixtures for integration tests (use transactions/rollbacks).
- **`fake_redis` / `redis_server`**: in-memory or docker-backed redis for pub/sub tests.
- **`patch_subprocess` / `fake_subprocess`**: intercept calls that would invoke external binaries.
- **`caplog` / `capsys`**: capture logs and stdout/stderr for assertions.

## Mocking External Tools

- Wrap external binaries behind adapter functions in your code (e.g., `run_subfinder()` or `fetch_wayback_results()`); tests can then monkeypatch those adapters instead of stubbing low-level `subprocess` calls everywhere.
- For code that calls `subprocess` directly, use `monkeypatch.setattr(subprocess, "run", fake_run)` or a small helper fixture that emulates the expected `CompletedProcess`.
- Use HTTP-level recording tools (VCR, `httpx_mock`) for external HTTP services to make tests repeatable.
- Prefer test doubles and fixtures over running real third-party tools in CI to avoid flakiness and long runtimes.

### 🔒 Hermetic Unit Testing & Plugin Mocking Policy
When writing unit tests for modules that register dynamic plugins (such as subdomain enumeration or passive collectors under `src.recon.subdomains`), follow these critical guidelines:
- **Avoid high-level patches**: Do not patch high-level module functions (like `fetch_crtsh_subdomains`) if they are registered into a global plugin registry loop at module import time. The registry will retain a reference to the original unpatched function object, causing the tests to bypass the mock and execute live HTTP requests.
- **Intercept the concrete low-level interface**: Always patch the underlying low-level interface library or function. For instance, patch `requests.get` inside the plugin's namespace (e.g., `"src.recon.subdomains.requests.get"`) to return a mock response. This guarantees that all execution paths are safely intercepted, preventing accidental external network traffic and keeping the unit test suite extremely fast and 100% hermetic.

## How To Test Without Real Binaries

- Create small fake executables in a test `bin/` directory and prepend that directory to `PATH` in a fixture.
- Use `monkeypatch.setattr(subprocess, "run", fake_run)` to intercept calls.

### Concrete Example: Testing Stage Merging

```python
import pytest
from src.core.contracts.pipeline_runtime import StageInput, StageOutput, StageOutcome
from src.pipeline.services.pipeline_orchestrator._state_helpers import merge_stage_output

def test_stage_output_replaces_state_delta(ctx):
    # Initial state
    ctx.result.subdomains = {"initial.com"}
    
    # Stage output that should replace initial state
    output = StageOutput(
        stage_name="recon",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=1.0,
        state_delta={"subdomains": ["new.com", "another.com"]}
    )
    
    merge_stage_output(ctx, "recon", output)
    
    # Verify replacement (not union)
    assert ctx.result.subdomains == {"new.com", "another.com"}
    assert "initial.com" not in ctx.result.subdomains
```

## Coverage Expectations

- Aim for high, meaningful coverage on core modules; suggested baseline is:
	- Project-wide: >= 80% (informational; enforce if desired).
	- New modules: aim for >= 80% coverage of the module's logic and full unit-test coverage of edge cases.
	- Critical infrastructure modules: consider >= 90% where practical.
- Prefer focused tests with clear assertions over artificially raising coverage numbers.
- CI should publish `coverage.xml` (`pytest --cov=src --cov-report=xml`) and compare against historical runs to detect regressions.

## 🛡️ Automated Quality Gates & Pipeline Security Verification

To secure the continuous delivery pipeline against supply chain attacks, dependency drifts, contract breaks, and accessibility regressions, the CI pipeline enforces five mandatory quality gates. These gates reside in the `scripts/` directory and can be executed locally:

### 1. Dependency Lockdown Check (`verify_dependency_pins.py`)
- **Purpose**: Enforces strict dependency version lockdown rules. It audits `pyproject.toml` and requires absolute double-equals (`==`) version definitions, blocking range operators (`>=`, `<=`, `~=`, etc.) which could expose the pipeline to upstream hijackings.
- **Command**:
  ```bash
  python scripts/verify_dependency_pins.py
  ```

### 2. CycloneDX SBOM Integrity Check (`validate_sbom.py`)
- **Purpose**: Compares software bill of materials (SBOM) component lists against the secure baseline at `configs/sbom-baseline.json` to block unauthorized package additions or version deviations.
- **Command**:
  ```bash
  python scripts/validate_sbom.py
  ```

### 3. Visual Layout & WCAG 2.2 AA Audit (`verify_a11y.py`)
- **Purpose**: Scans compiled frontend pages for compliance landmark structures, missing ARIA tags, missing image alt attributes, and visual outlines/default focus ring styling bypasses.
- **Command**:
  ```bash
  python scripts/verify_a11y.py
  ```

### 4. OpenAPI Contract Stability Auditor & Doc Sync (`validate_openapi.py`)
- **Purpose**: Dynamically compiles the active FastAPI dashboard schema and compares response/request schemas against `configs/openapi-baseline.json` to block breaking schema modifications. It enriches the spec with `x-ai-metadata` and path-level `x-ai-` tags (including the remediation verify endpoint) and automatically synchronizes the machine-readable YAML block in `docs/api-reference.md`. In CI, it fails if committed docs drift from the active schema.
- **Commands**:
  - Run checks only (fails if out-of-sync):
    ```bash
    python scripts/validate_openapi.py
    ```
  - Automatically rewrite and synchronize `docs/api-reference.md` with the active spec:
    ```bash
    python scripts/validate_openapi.py --write
    ```

### 5. Bundle Secret Scan & Attestation (`verify_bundle_secrets.py`)
- **Purpose**: Runs high-entropy signature regex scans across all build assets to guarantee no committed secrets, AWS credentials, generic API keys, private keys, or Slack webhooks leak to the distribution package.
- **Command**:
  ```bash
  python scripts/verify_bundle_secrets.py
  ```

## Example: Required Tests for New Modules

- New detector modules: include unit tests for logic and edge cases plus regression tests that encode known problematic inputs. Add integration tests when the detector interacts with pipelines, external services, or shared state.

Local quick commands

```bash
# Run unit tests
pytest tests/unit/

# Run architecture boundary tests
pytest tests/architecture/

# Run integration tests
pytest tests/integration/

# Run e2e (may require external services/tools)
pytest tests/e2e/

# Run all tests
pytest
```

Notes

- Ensure you have a working virtualenv and dev dependencies installed: `pip install -e .[dev]`.
- Some tests (integration/e2e) may expect `config.json` or external CLIs (subfinder, httpx, waybackurls, nuclei) on PATH — run with `--dry-run` for pipeline CLI to avoid invoking external binaries.
- Use markers to select tests: `pytest -m "not e2e"` or `pytest -m integration`.
- To collect tests without running: `pytest --collect-only`.

CI recommendations

- Create a matrix job for Python versions you support (this project targets Python 3.14+).
- Install system dependencies as needed for external tools or stub them out in CI if not required for the test suite.
- Run `pip install -e .[dev]`, then `ruff check .`, `mypy .` and `pytest -q` as part of the pipeline.
- For coverage, use: `pytest --cov=src --cov-report=xml` and publish the XML to your coverage service.

Debugging failing tests

- Re-run failing tests with `-k` and `-q` to isolate them.
- Use `pytest -s` to see stdout from tests.
- Many test helpers live under `tests/conftest.py` — review fixtures when a test depends on environment setup.
