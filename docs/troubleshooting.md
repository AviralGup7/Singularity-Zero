# Troubleshooting Logic (AI-Agent Guide)

This document provides a parseable decision tree for identifying and resolving pipeline execution failures.

---

## 🔍 Troubleshooting Decision Tree (Machine-Readable)

```yaml
failure_diagnosis:
  at_startup:
    checks:
      - target: "Redis connection"
        remedy: "Check REDIS_URL and ensure port 6379 is reachable"
      - target: "Tool PATH"
        remedy: "Verify 'subfinder', 'httpx', 'nuclei' are in $PATH"
      - target: "Template Provenance / Signature Failures"
        remedy: "Template signature verification is currently disabled because configs/templates/ does not exist yet. To enable it, create configs/templates/manifest.json and configs/templates/manifest.json.sig Set NUCLEI_SIGNATURE_PUBLIC_KEY environment variable to match the Ed25519 signing key."

  during_discovery:
    checks:
      - target: "Zero subdomains found"
        remedy: "Verify DNS resolution and check crt.sh connectivity"
      - target: "Timeout in subfinder"
        remedy: "Increase 'subdomains' stage timeout in flow_manifest"

  during_mining:
    checks:
      - target: "High URL collection timeouts"
        remedy: "Reduce 'katana' concurrency and check WAF blocking"
      - target: "Zero URLs harvested"
        remedy: "Check 'gau' connectivity and archive availability"

  during_execution:
    checks:
      - target: "Worker stall"
        remedy: "Check worker logs (port 8008) for MemoryError or process hangs"
      - target: "Empty findings"
        remedy: "Verify nuclei templates are present and target is reachable"

  during_reporting:
    checks:
      - target: "Template error"
        remedy: "Validate findings.json schema vs Jinja2 template"
      - target: "Disk space full"
        remedy: "Clean up 'output/cache/' and old checkpoints"

  dashboard_access:
    checks:
      - target: "CSRF token verification failed (code: csrf_token_failed)"
        remedy: "Ensure cookies are preserved. The csrf_token cookie is now HttpOnly=True for maximum XSS protection. JavaScript SPA clients must fetch the token value from the secure 'GET /api/csrf-token' endpoint on app bootstrap or form mount and supply it in the 'X-CSRF-Token' request header on mutating requests."
      - target: "Access denied to target / Scoping error (403 Forbidden)"
        remedy: "Verify that the request has the X-Tenant-ID header matching the target owner, or check JWT claims to ensure tenant_id is matching. Security violations are automatically audit-logged under event type 'tenant_violation'."
```

---

## 🛠️ Automated Remediation Commands

Agents can use these "last resort" commands to recover the system:

- **Reset Mesh Workers**:
  ```bash
  # Remove dead worker from the global registry
  redis-cli SREM queue:security-pipeline:workers <dead-worker-id>
  # Delete worker metadata
  redis-cli DEL queue:security-pipeline:worker:<dead-worker-id>
  ```
- **Clear Stale Checkpoints**:
  ```bash
  rm -rf output/<target>/checkpoints/*
  ```
- **Force Cache Refresh**:
  ```bash
  cyber-pipeline --config config.json --scope scope.txt --refresh-cache
  ```

---

## 🤖 Health Status Map

| Status | Interpretation | Agent Action |
|--------|----------------|--------------|
| `unhealthy:redis` | Queue backend is down | Pause all scans, wait for reconnect. |
| `unhealthy:mesh` | No workers available | Scale up mesh workers or switch to standalone. |
| `degraded:performance` | Stage duration > 2x baseline | Analyze logs for rate-limiting patterns. |

---

## 🌐 Network & Port Conflicts (Windows/WSL2/Termux Mesh)

When connecting standalone sub-nodes (e.g., Android devices running Termux) to a Redis backplane hosted on a Windows PC or WSL2 environment, you may experience connection timeouts or `Connection reset by peer` errors.

### 1. Windows IP Helper Service Conflict (`iphlpsvc`)
* **Problem**: The Windows IP Helper service (`iphlpsvc`) binds to port `6379` by default on all host network interfaces. If you attempt to use `netsh interface portproxy` to route external traffic on port `6379` directly to your local Redis instance, the connection will fail or be reset because traffic hits the Windows IP Helper service rather than Redis.
* **Symptoms**:
  - `Connection reset by peer` in `worker_lite.py` or other clients.
  - Port `6379` appears listening on the host but does not serve Redis protocol payloads.
* **Remediation**:
  Use a different external port (e.g., `16379`) for port proxying, and forward it to your local Redis port `6379`:
  ```powershell
  # Forward incoming traffic on port 16379 to local Redis on port 6379
  netsh interface portproxy add v4tov4 listenport=16379 listenaddress=0.0.0.0 connectport=6379 connectaddress=127.0.0.1
  ```
  Ensure you allow inbound traffic on port `16379` in your Windows Defender Firewall.
  Then connect the worker using:
  ```bash
  python worker_lite.py --redis-url redis://<YOUR_PC_IP>:16379/0
  ```

### 2. WSL2 vs Host Network Binding
* **Problem**: If Redis is running inside a WSL2 container and you are using `localhost` or `127.0.0.1`, external network devices cannot reach it unless bridged or explicitly proxied.
* **Remediation**: Ensure Redis binds to `0.0.0.0` or use the Windows host IP address with appropriate `netsh portproxy` rules to bridge the host OS Wi-Fi/Ethernet interface to the WSL2 virtual subnet.

