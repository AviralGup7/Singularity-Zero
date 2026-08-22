# CI/CD Integration Guide

The Cyber Security Test Pipeline provides first-class support for Continuous Integration and Continuous Delivery (CI/CD) workflows (GitHub Actions, GitLab CI, Azure Pipelines, Jenkins).

---

## 1. Exit-Code Taxonomy

The pipeline implements an explicit exit-code taxonomy allowing CI/CD workflows to distinguish between operational infrastructure issues and legitimate vulnerability policy violations:

| Exit Code | Constant | Meaning | Description |
|---|---|---|---|
| `0` | `EXIT_OK` | Clean Pass | Pipeline completed successfully; all findings are within policy thresholds. |
| `1` | `EXIT_ERROR` | Generic Error | General error (or collapsed exit code under `--legacy-exit-codes`). |
| `2` | `EXIT_POLICY_VIOLATION` | Policy Breach | Legitimate security findings exceeded configured policy thresholds (e.g. Critical finding discovered). |
| `3` | `EXIT_INFRA_FAILURE` | Infrastructure Failure | Fatal network outage, target unreachable, or missing required tool binary. |
| `4` | `EXIT_PARTIAL` | Partial Run | Non-fatal stages failed, but usable reports and partial findings were preserved. |
| `130` | `EXIT_INTERRUPTED` | Interrupted | Execution aborted via `SIGINT` / `SIGTERM`. |

---

## 2. Declarative Policy File (`policy.toml`)

Control merge gating thresholds by supplying a declarative policy file:

```toml
[on_findings]
max_critical = 0             # 0 critical vulnerabilities allowed (fail build immediately)
max_high = 2                 # Allow at most 2 high vulnerabilities
max_medium = 25              # Allow up to 25 medium vulnerabilities
allow_false_positive = true  # Analyst-confirmed FPs do not trigger policy failure
branch_glob = "main"         # Apply policy strictly to main branch merges

[on_infra]
fatal_stages = ["live_hosts"]
degraded_stages = ["subdomains", "urls"]

[on_failure]
treat_partial_as = 4
```

Execute a policy-gated scan:
```bash
python -m src.pipeline.runtime \
  --config configs/config.json \
  --scope configs/scope.txt \
  --policy policy.toml
```

---

## 3. SARIF 2.1.0 Ingestion

Every pipeline run automatically exports a standard SARIF 2.1.0 report (`report.sarif`), which can be ingested directly into GitHub Advanced Security, GitLab SAST/DAST tabs, and SonarQube:

### GitHub Actions Workflow Example:

```yaml
name: Security Pipeline Scan

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1' # Weekly Monday night scan

jobs:
  security_scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Install CSTP & Tools
        run: |
          pip install -e .
          cstp system setup

      - name: Execute Security Scan
        run: |
          cstp scan run --config configs/config.json --scope configs/scope.txt
        continue-on-error: true

      - name: Upload SARIF Report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: output/report.sarif
```

---

## 4. Incremental Differential Scanning

For high-velocity feature branch scans, incremental scanning re-probes only endpoints associated with modified code files:

```bash
python -m src.pipeline.runtime \
  --config configs/config.json \
  --scope configs/scope.txt \
  --incremental \
  --base-ref origin/main
```
