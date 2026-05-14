# Troubleshooting Logic (AI-Agent Guide)

This document provides a parseable decision tree for identifying and resolving pipeline execution failures.

---

## 🔍 Troubleshooting Decision Tree (Machine-Readable)

```yaml
failure_diagnosis:
  at_startup:
    checks:
      - target: "config.json syntax"
        remedy: "Validate against 'configs/schemas/config.schema.json'"
      - target: "Redis connection"
        remedy: "Check REDIS_URL and ensure port 6379 is reachable"
      - target: "Tool PATH"
        remedy: "Verify 'subfinder', 'httpx', 'nuclei' are in $PATH"

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
