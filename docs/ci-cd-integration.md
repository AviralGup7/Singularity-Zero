# CI/CD Integration

Canonical workflow: `.github/workflows/ci.yml` (GitHub Actions workflow id `276806682`). Quality philosophy: [testing.md](testing.md). Exit codes: [getting-started.md](getting-started.md) and `src/jobs/run_outcome.py`.

## Headless scan in CI

```bash
python -m src.pipeline.runtime \
  --config configs/config.json \
  --scope configs/scope.txt \
  --policy policy.toml
```

Optional flags: `--dry-run`, `--force-fresh-run` (or `--fresh` via `cstp scan`), `--resume-from <id>`, `--ci-fail-on-severity <critical|high|medium|low|info>`, `--legacy-exit-codes` (collapses 2/3/4 → 1).

SARIF is produced by the `sarif_export` stage (`src/reporting/sarif_exporter.py`) when the DAG reaches it. `reporting` is a join sink: it waits until every finding producer is **terminal**.

## Workflow jobs (live)

```text
Push to main
 ├─ lint          ruff + format + Bandit HIGH (no continue-on-error) + detect-secrets
 ├─ mypy
 ├─ typescript    tsc --noEmit (root tsconfig `files: []` is empty on purpose)
 ├─ frontend      eslint + build (gzip budgets in frontend config)
 ├─ test matrix   unit-infra, unit-core, unit-pipeline, unit-recon,
 │                unit-analysis, unit-dashboard, unit-exploit, unit-app, suites
 ├─ coverage      combine shards; fail_under = 45 (hard)
 ├─ security-audit
 ├─ security-scan Bandit/Semgrep (Semgrep `config: p/ci`, no auditOn: push)
 ├─ hardening
 ├─ iac-scan      Checkov 3.2.266, framework yaml, soft_fail: false
 └─ CI passed     needs all of the above; fail-fast: false on the test matrix
```

Per-test timeout: `pytest-timeout`, CI `PYTEST_ADDOPTS --timeout=20 --timeout-method=signal`. Job-level 12 minutes. Combined coverage is the hard gate; per-shard `--cov-fail-under=0`.

Do **not**:

- CI-fail on `REPLACE_WITH_` in `deploy/kubernetes/secrets.yaml` (undeployable template).
- Flip coverage / Bandit / Semgrep / Checkov back to soft-fail.
- Unskip fail-fast recon tests until the scheduler contract is rewired.
- Run the full suite locally. Agents: smallest relevant slice, ≤ ~50 seconds.

## Policy gate

`policy.toml` via `--policy`. Exit **2** is COMPLETED with findings over threshold, not a crash. Exit **3** is infrastructure / attach failure / fatal recon. Exit **4** is degraded.
