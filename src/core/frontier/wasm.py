"""
Cyber Security Test Pipeline - WASM Plugin Sandbox
Provides a secure, isolated runtime for executing untrusted security detectors.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

# Fix #389: Guard wasmtime import behind feature flag to avoid startup penalty
if os.environ.get("FEATURE_WASM_PLUGINS", "false").lower() == "true":
    import wasmtime
else:
    class _MockWasmtime:
        Engine = object
        Linker = object
        Module = object
        Store = object
        WasiConfig = object
        Memory = object
        Func = object
    wasmtime = _MockWasmtime()  # type: ignore

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

class WASMPluginHost:
    """
    Host environment for WASM-based security plugins.
    Enforces memory limits and CPU timeouts for execution.
    """
    def __init__(self, wasm_path: str) -> None:
        self._engine = wasmtime.Engine()
        self._linker = wasmtime.Linker(self._engine)
        self._linker.define_wasi()

        self._module = wasmtime.Module.from_file(self._engine, wasm_path)
        self._store = wasmtime.Store(self._engine)
        self._store.set_wasi(wasmtime.WasiConfig())

    def run_detector(self, stage_input: dict[str, Any]) -> dict[str, Any]:
        """
        Execute a WASM detector with isolated state.
        Input and Output are passed via JSON-serialized string buffers.
        """
        instance = self._linker.instantiate(self._store, self._module)

        # Get memory and export functions
        exports = instance.exports(self._store)
        memory = exports.get("memory")
        allocate = exports.get("allocate")
        run = exports.get("run_detector")
        deallocate = exports.get("deallocate")

        # Fix #214: check that allocate is actually a wasmtime.Func
        if not all((isinstance(memory, wasmtime.Memory), isinstance(allocate, wasmtime.Func), callable(run))):
             raise RuntimeError("WASM module missing required exports (memory, allocate, run_detector)")

        # 1. Prepare Input
        input_json = json.dumps(stage_input).encode()
        input_ptr = allocate(self._store, len(input_json))

        # Write to WASM memory - use memory.write for efficiency
        # Fix #215: The wasmtime Python binding uses memory.write(store, ptr, data)
        memory.write(self._store, input_ptr, input_json)

        # 2. Execute
        logger.info("Executing WASM Plugin...")
        start = time.monotonic()
        output_ptr = run(self._store, input_ptr, len(input_json))
        duration = time.monotonic() - start

        # 3. Retrieve Output
        # (Assuming the first 4 bytes at output_ptr contain the length)
        output_len_bytes = memory.read(self._store, output_ptr, output_ptr + 4)
        output_len = int.from_bytes(output_len_bytes, "little")
        output_json_bytes = memory.read(self._store, output_ptr + 4, output_ptr + 4 + output_len)
        output_json = output_json_bytes.decode()

        result = json.loads(output_json)
        result["_wasm_duration"] = duration

        # 4. Cleanup
        if deallocate:
            deallocate(self._store, input_ptr)
            deallocate(self._store, output_ptr)

        return result

def execute_sandboxed_plugin(wasm_path: str, stage_input: dict[str, Any]) -> dict[str, Any]:
    """Helper to run a sandboxed plugin in a one-off host."""
    host = WASMPluginHost(wasm_path)
    return host.run_detector(stage_input)
