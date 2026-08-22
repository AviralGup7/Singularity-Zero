# Troubleshooting & Diagnostic Guide

This document provides a structured diagnostic decision tree and remediation procedures for resolving pipeline, worker, mesh, and dashboard execution issues.

---

## 🔍 Diagnostic Decision Tree

```yaml
failure_diagnosis:
  at_startup:
    checks:
      - target: "Redis connectivity failure"
        symptom: "ConnectionRefusedError or Redis Timeout"
        remedy: "Verify REDIS_URL and ensure Redis server is running (e.g. docker compose up -d redis)."
      - target: "Missing binary dependencies"
        symptom: "FileNotFoundError: [Errno 2] No such file or directory: 'nuclei'"
        remedy: "Run 'cstp system setup' to download pre-compiled binaries to .tools/bin or add Go tools to $PATH."
      - target: "Configuration schema mismatch"
        symptom: "ValidationError in ConfigLoader"
        remedy: "Run 'cstp system doctor' to validate config.json against configs/config.schema.json."

  during_recon_and_discovery:
    checks:
      - target: "Zero subdomains discovered"
        symptom: "Recon stage completes with 0 results"
        remedy: "Check network connectivity to crt.sh/AlienVault; verify scope syntax in configs/scope.txt."
      - target: "DNS resolution timeout"
        symptom: "dnsx or massdns timeout warnings"
        remedy: "Verify upstream resolvers in config.json or check local firewall UDP 53 rules."

  during_active_analysis:
    checks:
      - target: "Circuit Breaker TRIPPED to OPEN"
        symptom: "Stage logs show 'CircuitBreaker: OPEN (rate limit detected)'"
        remedy: "Target host is returning HTTP 429; orchestrator will automatically honor Retry-After headers."
      - target: "Zero findings emitted on known-vulnerable host"
        symptom: "Scan completes cleanly with empty findings"
        remedy: "Check FAILURE_MODES.md; verify that active modules are enabled in config and nuclei templates match target technology."

  dashboard_and_auth:
    checks:
      - target: "401 Unauthorized / Token Expired"
        symptom: "API requests return HTTP 401"
        remedy: "Re-authenticate at /login or provide valid Authorization: Bearer <token> or X-API-Key header."
      - target: "403 Forbidden / Tenant Context Violation"
        symptom: "Access denied to target or job"
        remedy: "Ensure the X-Tenant-ID header matches the target asset owner."
```

---

## 🛠️ Operational Recovery & Diagnostic Commands

- **Run System Diagnostic Doctor**:
  ```bash
  cstp system doctor
  ```

- **Inspect Infrastructure Health**:
  ```bash
  cstp system status
  ```

- **Purge Stale Checkpoints & Cached Artifacts**:
  ```bash
  cstp system cleanup --days 3
  ```

- **Force Clean Scan Run (Bypassing Checkpoints)**:
  ```bash
  cstp scan run --config configs/config.json --scope configs/scope.txt --fresh
  ```

---

## 🌐 Network & Port Forwarding (Windows / WSL2 / Termux)

### Windows IP Helper Port Proxying (`iphlpsvc`)
On Windows hosts, the IP Helper service (`iphlpsvc`) may occupy port `6379` on external interfaces. To bridge remote worker sub-nodes (such as Termux on Android) to your host Redis:

```powershell
# Forward external port 16379 to local Redis port 6379
netsh interface portproxy add v4tov4 listenport=16379 listenaddress=0.0.0.0 connectport=6379 connectaddress=127.0.0.1
```

Connect the remote worker node:
```bash
python -m src.infrastructure.queue.worker_lite --redis-url redis://<HOST_IP>:16379/0
```
