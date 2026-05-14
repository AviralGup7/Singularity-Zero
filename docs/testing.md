# Testing and CI

This document summarizes how to run tests locally and recommendations for CI.

## Testing Strategy Philosophy

Testing should provide fast, reliable feedback to developers and CI. Favor many small, deterministic unit tests for core logic, use integration tests to validate interactions between components, add regression tests for confirmed bug fixes, and reserve end-to-end (e2e) tests for critical user or pipeline flows. Keep e2e tests narrow to reduce flakiness. Tests should be deterministic, isolated, and easy to run locally.

## What Belongs Where

- **Unit tests**: fast, isolated tests that exercise a single function or class. No network, no real binaries. Place these under `tests/unit/`, organized by domain (`tests/unit/core/`, `tests/unit/analysis/`, `tests/unit/pipeline/`, `tests/unit/recon/`, `tests/unit/dashboard/`, `tests/unit/execution/`, `tests/unit/api_tests/`, `tests/unit/reporting/`). New modules must include unit tests.
- **Integration tests**: verify interactions between multiple components (DB, HTTP clients, queues, filesystem). These may use real services (docker, test containers) or well-structured test doubles. Place under `tests/integration/`.
- **Regression tests**: small tests added to capture a previously-observed bug and prevent re-introduction. Put these in `tests/regression/` or next to the unit test that demonstrates the bug (name clearly to indicate the bug ID or root cause).
- **End-to-end (e2e) tests**: full-system workflows that exercise user-facing or pipeline flows. These are slower and more brittle; tag with `@pytest.mark.e2e` and run them in gated CI stages or on demand. Place under `tests/e2e/`.

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
