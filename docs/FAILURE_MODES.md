# Failure Modes & Diagnostics Handbook

This document provides a comprehensive operational guide for identifying, diagnosing, and triaging pipeline failure modes, circuit breaker trip conditions, and differentiating genuine "zero finding" scans from degraded scan states.

---

## 🎯 Findings vs. Silent Gaps

In automated security testing, distinguishing between a secure target and a degraded scan where tools failed silently is critical:

| Stage Status | Finding Count | Exit Code | Diagnostic Signature | Interpretation |
|---|---|---|---|---|
| **COMPLETED** | `0` | `0` | No degraded probes or unhandled errors | **Genuine Clean Target**: Target scanned successfully; no vulnerabilities detected. |
| **FAILED** | `0` | `3` | Fatal recon failure or target unreachable | **Infrastructure Failure**: Target offline or network path blocked. |
| **COMPLETED** | `0` | `4` | `degraded_probes` or `warnings` present | **Degraded Run**: Specific probes timed out or were blocked by target WAF. |
| **POLICY_VIOLATION** | `> 0` | `2` | Findings exceed `policy.toml` thresholds | **Vulnerabilities Found**: Exploits or vulnerabilities confirmed. |

---

## 🔍 Detailed Breakdown of Common Failure Modes

### 1. Reconnaissance Yields Zero URLs
- **Symptom**: Reconnaissance stage finishes with `0` discovered URLs; active scanning terminates immediately.
- **Root Cause**: Target domain does not resolve, DNS rate limits triggered, or target scope is misconfigured.
- **Remediation**: Check domain resolution (`nslookup <target>`) and verify `configs/scope.txt`.

### 2. Circuit Breaker Trips to OPEN (HTTP 429 Throttling)
- **Symptom**: Log contains `CircuitBreaker: OPEN (rate limit detected)` and active probing pauses.
- **Root Cause**: Target server or reverse proxy is rate limiting requests.
- **Remediation**: The orchestrator automatically extracts `Retry-After` headers and pauses stage workers. To prevent re-occurrence, lower probe concurrency in `configs/config.json`.

### 3. Exploit PoC Sandbox Execution Timeout
- **Symptom**: Finding verification stage flags candidate finding as `UNVERIFIED_TIMEOUT`.
- **Root Cause**: The validation script exceeded its allotted WASM / subprocess execution time quota.
- **Remediation**: Increase the validation timeout in `config.json` under `validation_timeout_seconds` or inspect the PoC script for infinite loops.

### 4. ML Severity Active Learning Degradation
- **Symptom**: Severity predictions fallback to static baseline or standard logistic regression.
- **Root Cause**: Compiled machine learning dependencies (`xgboost`, `scikit-learn`) unavailable in runtime environment.
- **Remediation**: The system automatically utilizes pure-NumPy fallback routines (`src/learning/`) ensuring inference continuity without crashing.