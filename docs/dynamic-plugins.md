# Dynamic Plugin SDK

The Cyber Security Test Pipeline supports hot-loading custom security checks, collectors, and validation modules from standalone Python files without restarting the pipeline or dashboard.

A ready-to-use plugin example is available at `docs/examples/dynamic_header_echo.py`.

---

## 📁 Watched Plugin Directories

The plugin runtime automatically scans and watches the following directory paths:
- `.pipeline/plugins/`
- `src/analysis/plugins/`
- `src/execution/validators/`
- `src/core/plugins/`

To add custom directories, set the `CYBER_PLUGIN_DIRS` environment variable to a path-separated list of directories.

---

## 📝 Plugin Manifest & Contract

A dynamic plugin defines a literal `PLUGIN_MANIFEST` dictionary and a callable entrypoint:

```python
PLUGIN_MANIFEST = {
    "id": "custom.header_echo",
    "name": "Header Echo Exposure Check",
    "version": "1.0.0",
    "kind": "analysis",
    "description": "Flags responses exposing sensitive debug headers.",
    "group": "exposure",
    "entrypoint": "run",
    "sandbox": "process",
    "enabled_by_default": True,
    "capabilities": ["passive-http"],
    "tags": ["headers", "exposure"],
    "timeout_seconds": 10,
}


def run(payload: dict) -> list[dict]:
    """Analyze HTTP response payload and return candidate findings."""
    response = payload.get("response", {})
    headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
    if "x-debug-trace" in headers:
        return [
            {
                "title": "Debug Trace Header Exposed",
                "severity": "low",
                "evidence": f"Found header X-Debug-Trace: {headers['x-debug-trace']}",
            }
        ]
    return []
```

### Supported Plugin Kinds (`kind`):
- `analysis`: Vulnerability detection logic evaluated during scan analysis stages.
- `validator`: Exploit and finding validation checks.
- `scanner`: Custom active probing routines.
- `recon`: Custom asset and subdomain discovery collectors.
- `exporter`: Custom report formatting and external sync sinks.

---

## 🔒 Tiered Sandboxing & Security Verification

Dynamic plugins execute inside a multi-tier sandbox:

1. **AST Validation (Pre-Execution)**:
   The plugin loader inspects the Python Abstract Syntax Tree (AST) before loading, blocking dangerous primitives (`eval`, `exec`, raw file writes, dynamic `__import__`).
2. **Process Isolation (`sandbox: "process"`)**:
   Plugins execute within isolated child processes communicating via JSON IPC over stdin/stdout with strict execution timeouts and memory quotas.
3. **WebAssembly Isolation (`sandbox: "wasm"`)**:
   Binary validators and untrusted WASM modules execute inside an isolated `wasmtime` runtime (`src/sandbox/`), preventing host filesystem or network access.

---

## 🌐 API & Runtime Integration

- `POST /api/registry/plugins/reload`: Manually triggers hot-reload of all plugin directories.
- `GET /api/registry/plugins`: Returns currently loaded, active, and rejected plugin manifests.
- `GET /api/registry/capabilities`: Exposes active plugin capabilities to the frontend scan builder.
