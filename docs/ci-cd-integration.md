# CI/CD Integration Guide

The pipeline exposes a **structured CI/CD contract** for modern continuous-integration
consumers (GitHub Actions, GitLab CI, Azure DevOps, Jenkins, CircleCI, etc.):

1. A **distinct exit-code taxonomy** that lets CI consumers disambiguate operational
   failure from a successful pentest that found real vulnerabilities.
2. A **SARIF 2.1 artifact** (`report.sarif`) consumable by code-scanning platforms
   as native code-scan alerts.
3. An **incremental scan mode** (`--incremental --base-ref <ref>`) that re-scans only
   the endpoints mapped to files changed since `<ref>`, using the most recent prior
   run's recon data for the URL→path mapping.
4. An **`INGRESS_POLICY_RESULT` event** on the process-wide event bus so external
   policy engines can subscribe to the run's policy verdict.
5. A **declarative policy file** (`policy.toml`) for `on_findings` severity thresholds,
   `on_infra` fatal-stage classification, and `on_failure` partial-run handling.

---

## 1. Exit-Code Taxonomy

| Code | Constant | Meaning | When |
|------|----------|---------|------|
| `0`  | `EXIT_OK`              | pass             | Clean run, no policy violation |
| `1`  | (legacy)               | error            | `--legacy-exit-codes` opt-in |
| `2`  | `EXIT_POLICY_VIOLATION`| policy_violation | Findings exceed policy thresholds |
| `3`  | `EXIT_INFRA_FAILURE`   | infra_failure    | Fatal recon, network, tool missing |
| `4`  | `EXIT_PARTIAL`         | partial          | Non-fatal stages failed, report usable |
| `130`| (signal)               | interrupted      | SIGINT/SIGTERM |

A run that finds 12 critical findings on a `main` branch run exits `2` (a successful
pentest outcome). A run that cannot reach the target exits `3` (an operational
failure). A run that completes reporting despite a degraded `semgrep` stage exits
`4`. CI scripts can branch on these codes to drive merge gating, alert routing,
and incident creation.

For full back-compat, pass `--legacy-exit-codes` to collapse `2/3/4` back to `1`.

The policy evaluation is persisted at `<run_dir>/policy_evaluation.json` for
post-hoc audit. The event-bus payload is also available to subscribers.

---

## 2. Policy File (`policy.toml`)

```toml
# Fail the run on any critical finding, allow up to 5 highs, 50 mediums.
[on_findings]
max_critical = 0
max_high = 5
max_medium = 50
max_low = 1000
allow_false_positive = true   # findings marked FP by AI triage are excluded
exclude_categories = ["info-disclosure", "fingerprint"]
branch_glob = "main"           # only apply on `main` (fnmatch syntax)

# Stages whose failure aborts the run (exit 3).  ``live_hosts`` is
# the only truly fatal recon stage in the default policy because it
# gates every active scanner.  Operators that want the old
# "any-failed-recon-is-fatal" behaviour can list every recon stage
# here, but doing so disables the degraded-continue path documented
# below.
[on_infra]
fatal_stages = ["live_hosts"]
# Stages whose failure is allowed to continue in degraded mode if a
# downstream recon stage still produced actionable output.  When a
# degraded stage fails but ``urls`` (or ``subdomains`` for the reverse
# case) still surfaced targets, a ``RECON_DEGRADED`` warning is
# emitted and the run is downgraded to ``partial`` (exit 4) instead
# of ``infra_failure`` (exit 3).  This maximises findings yield for
# bug-bounty hunters who want data from every reachable stage.
degraded_stages = ["subdomains", "urls"]

# Map partial runs to a specific exit code.
[on_failure]
retryable_only = false        # false ⇒ all infra failures non-zero exit
treat_partial_as = 4            # 0, 2, or 4
```

Load it with:

```bash
cyber-pipeline --config configs/config.json --scope scope.txt --policy policy.toml
```

Or via the config file's `ci.policy` field. A bad policy file is treated as a
configuration error — the run aborts pre-flight with `PolicyLoadError`.

The default policy (no `--policy` flag) allows up to 5 highs and 50 mediums per
run, marks only `live_hosts` failures as infra, treats `subdomains`/`urls`
failures as *degraded* (downgraded to `partial` if downstream salvaged), and
treats partial runs as exit `4`.

Branch detection falls back to `GITHUB_REF_NAME` → `CI_COMMIT_REF_NAME` →
`BRANCH_NAME` → `CYBER_BRANCH` → `--branch` in that order.

---

## 3. SARIF 2.1 Output

Every run now produces `<run_dir>/report.sarif` alongside the existing HTML/JSON
reports. The document is SARIF 2.1.0 with:

* `tool.driver.name = "cyber-security-test-pipeline"`
* Per-finding `ruleId`, `level` (error/warning/note), `message.text`,
  `locations[0].physicalLocation.artifactLocation.uri` (the URL), and
  `partialFingerprints.primary` (stable SHA-256-derived dedupe key).
* CWE tags in `rule.properties.tags` and a `security-severity` CVSS approximation
  on each rule.
* False-positive findings (lifecycle_state = `FALSE_POSITIVE` or AI
  `triage_decision = "FP"`) are filtered out by default so CI doesn't raise
  alerts on known FPs. Pass `ci.include_false_positives_in_sarif = true` in
  config to include them.

### GitHub Code Scanning

```yaml
# .github/workflows/security.yml
- name: Run pipeline
  run: |
    cyber-pipeline \
      --config configs/config.json \
      --scope scope.txt \
      --policy policy.toml

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: output/example.com/${{ github.run_id }}/report.sarif
```

### GitLab

```yaml
artifacts:
  reports:
    sast: output/example.com/$CI_PIPELINE_ID/report.sarif
```

### Azure DevOps

Add the [SARIF SAST Scans Tab](https://marketplace.visualstudio.com/items?itemName=ms-devlabs.sarif-saas) extension and
upload the file via `PublishBuildArtifacts@1`.

---

## 4. Incremental Scans (`--incremental --base-ref`)

```bash
cyber-pipeline \
  --config configs/config.json \
  --scope scope.txt \
  --incremental \
  --base-ref origin/main
```

When enabled, the new `git_diff_crawl` stage runs after `urls` and:

1. Reads the most recent prior run's `priority_scores.json` (under
   `<target_root>/<run_id>/priority_scores.json`) to build the URL→path map.
2. Runs `git diff --name-only <base_ref> HEAD` to list changed files.
3. Filters the URL set to URLs whose path matches a changed file (basename match
   for `api/users.py` ⇄ `…/api/users`, full-path substring as fallback).
4. Overwrites `ctx.urls` and the priority URL set so the rest of the pipeline
   (parameter extraction, ranking, scanning) operates on the reduced scope.

### When it skips

* `--incremental` is not set (full crawl).
* No `--base-ref` provided.
* No prior run exists (cold start) — falls back to a full crawl.
* `git diff` errors out (not a git repo, ref missing, dirty index) — the stage
  marks itself `FAILED` with `reason="git_diff_failed"` and the orchestrator
  records it as a partial failure (exit 4), not infra (exit 3).

### URL→Path Mapping

The mapping is intentionally permissive because the inverse (file → URL) is
application-specific:

| File changed | URL match |
|--------------|-----------|
| `api/users.py`        | `https://example.com/api/users` (basename match) |
| `src/routes/api/users.py` | `https://example.com/api/users` (substring) |
| `frontend/src/components/Search.tsx` | (no URL match — full crawl for static assets) |

For non-standard layouts, supply your own URL→path list by populating the prior
run's `priority_scores.json` with a `path` field per entry.

---

## 5. Event Bus: `INGRESS_POLICY_RESULT`

When the orchestrator finishes evaluating the policy, it emits a
`INGRESS_POLICY_RESULT` event on the process-wide event bus so external policy
engines can subscribe:

```python
from src.core.events import EventType, get_event_bus

def on_policy(event):
    payload = event.data["evaluation"]
    if payload["exit_code"] == 2:
        notify_security_team(payload["violations"])

get_event_bus().subscribe(EventType.INGRESS_POLICY_RESULT, on_policy)
```

Payload shape (`event.data["evaluation"]`):

```json
{
  "exit_code": 2,
  "outcome": "policy_violation",
  "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
  "violations": ["critical=1 > max_critical=0"],
  "failed_stages": [],
  "partial": false,
  "branch": "main",
  "policy_snapshot": { "on_findings": {...}, "on_infra": {...}, "on_failure": {...} }
}
```

---

## 6. CLI Reference

| Flag | Description |
|------|-------------|
| `--policy PATH`       | Path to a `policy.toml` file. Omit for default thresholds. |
| `--incremental`       | Restrict the URL set to URLs mapped to files changed since `--base-ref`. |
| `--base-ref REF`      | Git ref (branch/tag/commit) for the incremental diff baseline. |
| `--branch NAME`       | Current branch (used by `[on_findings] branch_glob`). Falls back to `GITHUB_REF_NAME` / `CI_COMMIT_REF_NAME`. |
| `--legacy-exit-codes` | Collapse `2/3/4` back to `1` for back-compat. |
| `--replay PATH`       | Replay a prior run from a `.tar.gz` archive. Still emits the full exit-code taxonomy. |

---

## 7. Programmatic API

```python
from src.pipeline.services.ci import (
    ExitConditionPolicy,
    evaluate_policy,
    load_policy,
)
from src.pipeline.services.ci.policy import (
    EXIT_INFRA_FAILURE, EXIT_OK, EXIT_PARTIAL, EXIT_POLICY_VIOLATION,
)

policy = load_policy("policy.toml")
evaluation = evaluate_policy(
    policy,
    findings=reportable_findings,
    failed_stages=stage_metrics,
    branch="main",
)
if evaluation.exit_code == EXIT_POLICY_VIOLATION:
    block_merge(evaluation.violations)
```

The SARIF exporter can also be called directly:

```python
from src.reporting.sarif_exporter import export_findings_to_sarif, merge_sarif_documents

result = export_findings_to_sarif(findings, include_false_positives=False)
run_dir.mkdir(parents=True, exist_ok=True)
(run_dir / "report.sarif").write_text(json.dumps(result.document, indent=2))
```

---

## 8. Source Map

| Concern | File |
|---------|------|
| Exit-code policy + TOML loader | `src/pipeline/services/ci/policy.py` |
| Orchestrator integration (resolve, emit, persist) | `src/pipeline/services/pipeline_orchestrator/_run_execution.py` |
| SARIF conversion | `src/reporting/sarif_exporter.py` |
| SARIF stage | `src/pipeline/services/pipeline_orchestrator/stages/sarif_export.py` |
| Incremental git-diff stage | `src/pipeline/services/pipeline_orchestrator/stages/git_diff_crawl.py` |
| CLI flags | `src/pipeline/runner_support.py` |
| Event types | `src/core/events.py` |
| Tests | `tests/unit/pipeline/test_exit_policy.py`, `test_sarif_exporter.py`, `test_git_diff_crawl.py` |
