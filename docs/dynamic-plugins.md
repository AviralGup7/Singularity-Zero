# Dynamic Plugin SDK

Scaffolding exists. WASM is feature-flagged. This is not a second plugin registry.

## Scaffold

```bash
cstp plugin new --name custom_header_audit --category recon
```

Implemented in `src/cli/__init__.py` (`handle_plugin_new`). Valid categories are `--category recon`, `--category exploit`, and `--category reporting`.

## Registries (do not merge)

Two `PluginRegistry` implementations exist on purpose and are **not** being unified unless newly assigned:

- `src/core/plugins/framework.py`
- `src/core/plugins/registry.py`

`src/core/plugins/loader.py` may import `src.analysis`. `src/core/contracts/protocol_registry.py` must **not** lazy-import `JSONASTMutator`. `get_ast_mutator()` returns `None` if unregistered; `src/core/mutation_engine.py` always emits at least one `reason: "json_ast_mutation"` fallback.

## Runtime graph vs import-time graph

`STAGE_GRAPH` in `_constants.py` is built at import from `build_pipeline_graph`. After plugin registration the **runtime** graph can grow nodes (for example `sca_scan`, `container_scan`, `iac_scan`, `git_secret_scan` when the registry `produces` contains `"finding"`). `_join_finding_producers` adds those names to `reporting.needs`. Planner prefers the runtime Graph; import-time `STAGE_ORDER` is still used in some resume filters.

`STAGE_TIMEOUTS` in `_constants.py` does **not** list every graph node (`recon_validation`, `threat_modeling`, `subdomain_takeover`, sca/container/iac/git_secret, `ci_export`, `dedup_stage`, `scope`, …). Missing keys fall through to the default timeout.

## Sandbox

Plugins that shell out are admitted through `stage_admit.admit_stage`: authorize → consume (I28 `commit_requests`) → `ProcessSandbox.check_egress` (default `NetworkEgressFilter.metadata_guard()`). `ProcessSandbox.run` is unused. WASM: `FEATURE_WASM_PLUGINS=true` plus `src/execution/frontier/wasm.py`; default is `_MockWasmtime`.

## Tests

Architecture boundary tests in `tests/architecture/test_core_layer_contracts.py` forbid `src/core/**` from importing `src.fuzzing` / `src.recon` / `src.exploitation` / `src.reporting` / `src.analysis` / `src.decision` except the documented loader/mutator exceptions.
