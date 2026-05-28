# Dynamic Plugin SDK

The pipeline can hot-load third-party security checks from a single Python file.
Drop a file with a literal `PLUGIN_MANIFEST` and a JSON-callable entrypoint into
one of the watched directories and the dashboard/pipeline will discover,
validate, sandbox, register, and expose it without a restart.

A ready-to-drop example lives at `docs/examples/dynamic_header_echo.py`.

## Watched Directories

The default watched directories are:

- `.pipeline/plugins/`
- `src/core/frontier/plugins/`
- `src/analysis/plugins/`
- `src/execution/validators/validators/`
- `src/core/plugins/`

Set `CYBER_PLUGIN_DIRS` to an OS-path-separated list to add more directories.

## Plugin Contract

```python
PLUGIN_MANIFEST = {
    "id": "acme.header_echo",
    "name": "Header Echo Check",
    "version": "1.0.0",
    "kind": "analysis",
    "description": "Flags responses with an unsafe X-Debug header.",
    "group": "exposure",
    "entrypoint": "run",
    "sandbox": "process",
    "enabled_by_default": True,
    "capabilities": ["passive-http"],
    "tags": ["headers"],
    "timeout_seconds": 10,
}


def run(payload):
    response = payload.get("response", {})
    headers = response.get("headers", {})
    if "x-debug" not in {key.lower() for key in headers}:
        return []
    return [{"title": "Debug header exposed", "severity": "low"}]
```

`kind` may be `analysis`, `validator`, `scanner`, `enrichment`, `exporter`, or
`recon`. Analysis plugins are registered as scan checks and appear in the
dashboard registry and scan-presets dynamic plugin grid. Validator and pipeline
stage plugins are registered as sandboxed callables in the live plugin registry.

## Validation And Sandboxing

The platform utilizes a **Tiered Sandboxing Architecture** to isolate dynamic executable checks:

1. **Process-Based & AST validation (Python Plugins)**: 
   The loader parses plugin source using the `ast` module before registration. It requires a literal manifest, verifies the entrypoint exists, restricts imports to safe standard-library modules, blocks dynamic execution helpers (such as `eval`, `exec`, `open`, and `__import__`), and records invalid manifests for the UI.
   Once validated, loaded Python plugins execute in a separate, isolated child process through JSON stdin/stdout with a strict per-plugin timeout. This process boundary prevents untrusted plugin code from accessing orchestrator objects or sharing the primary memory pool.

2. **WebAssembly (WASM) Isolation (Binary / AEVE Verifiers)**:
   For binary validators and untrusted proof-of-concept executables, the platform requires full hardware-level memory and CPU isolation. This is handled by WebAssembly sandboxing via `wasmtime` (implemented in `src/core/frontier/wasm.py`), completely locking out host kernel access. The plugin manifest schema reserves `sandbox: "wasm"` for native WebAssembly plugin entries.

## Runtime Surfaces

- `src.core.plugins.loader.refresh_dynamic_plugins()` rescans and registers.
- `src.core.plugins.loader.start_dynamic_plugin_watcher()` starts hot reload.
- `/api/registry/plugins` returns loaded and invalid dynamic plugin manifests.
- `/api/registry/capabilities` returns the generated `CapabilityManifest`.
- `/api/registry/analysis` includes dynamic analysis checks for the frontend.
