"""
Cyber Security Test Pipeline - WASM Plugin Sandbox
Provides a secure, isolated runtime for executing untrusted security detectors.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, cast

from src.core.logging.audit import AuditEventType, get_audit_logger
from src.core.logging.trace_logging import get_pipeline_logger

# Fix #389: Guard wasmtime import behind feature flag to avoid startup penalty
if os.environ.get("FEATURE_WASM_PLUGINS", "false").lower() == "true":
    import wasmtime
else:

    class _MockWasmtime:
        class Engine:
            pass

        class Linker:
            def __init__(self, engine: Any) -> None:
                pass

            def define_wasi(self) -> None:
                pass

            def instantiate(self, store: Any, module: Any) -> Any:
                class _MockInstance:
                    def exports(self, _store: Any) -> dict[str, Any]:
                        return {}

                return _MockInstance()

        class Module:
            @staticmethod
            def from_file(engine: Any, path: str) -> Any:
                pass

        class Store:
            def __init__(self, engine: Any) -> None:
                pass

            def set_wasi(self, config: Any) -> None:
                pass

        class WasiConfig:
            pass

        class Memory:
            def write(self, store: Any, ptr: int, data: bytes) -> None:
                pass

            def read(self, store: Any, start: int, end: int) -> bytes:
                return b""

        class Func:
            def __call__(self, *args: Any) -> Any:
                pass

    wasmtime = _MockWasmtime()  # type: ignore

logger = get_pipeline_logger(__name__)

_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "bearer",
    "client_secret",
    "credential",
    "credentials",
    "password",
    "secret",
    "token",
    "waf_evasion",
    "waf_evasion_parameter",
}


def _redact_sensitive_input(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(token in lowered for token in _SENSITIVE_KEYS):
                digest = hashlib.sha256(str(item).encode("utf-8", errors="ignore")).hexdigest()
                redacted[str(key)] = {"_secret_ref": digest[:16], "redacted": True}
            else:
                redacted[str(key)] = _redact_sensitive_input(item)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_input(item) for item in value]
    return value


def _audit_wasm_secret_boundary(redacted_input: dict[str, Any]) -> None:
    try:
        get_audit_logger().log(
            AuditEventType.SECURITY_EVENT,
            "local",
            "wasm-plugin-host",
            "credential.wasm_boundary",
            "recorded",
            {"input_sha256": hashlib.sha256(json.dumps(redacted_input, sort_keys=True).encode()).hexdigest()},
        )
    except Exception:
        return


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
        if not (
            isinstance(memory, wasmtime.Memory)
            and isinstance(allocate, wasmtime.Func)
            and isinstance(run, wasmtime.Func)
        ):
            raise RuntimeError(
                "WASM module missing required exports (memory, allocate, run_detector)"
            )

        # 1. Prepare Input. Raw credentials are never passed into untrusted WASM.
        safe_stage_input = cast(dict[str, Any], _redact_sensitive_input(stage_input))
        _audit_wasm_secret_boundary(safe_stage_input)
        input_json = json.dumps(safe_stage_input).encode()
        input_ptr = cast(Any, allocate)(self._store, len(input_json))

        # Write to WASM memory - use memory.write for efficiency
        # Fix #215: The wasmtime Python binding uses memory.write(store, data, offset)
        cast(Any, memory).write(self._store, input_json, int(input_ptr))

        # 2. Execute
        logger.info("Executing WASM Plugin...")
        start = time.monotonic()
        output_ptr = cast(Any, run)(self._store, int(input_ptr), len(input_json))
        duration = time.monotonic() - start

        # 3. Retrieve Output
        # (Assuming the first 4 bytes at output_ptr contain the length)
        ptr = int(output_ptr)
        output_len_bytes = cast(Any, memory).read(self._store, ptr, ptr + 4)
        output_len = int.from_bytes(output_len_bytes, "little")

        if output_len == 0:
            return {"verified": False, "error": "empty_output"}

        output_json_bytes = cast(Any, memory).read(self._store, ptr + 4, ptr + 4 + output_len)
        output_json = output_json_bytes.decode()

        result = cast(dict[str, Any], json.loads(output_json))
        result["_wasm_duration"] = duration

        # 4. Cleanup
        if deallocate and isinstance(deallocate, wasmtime.Func):
            cast(Any, deallocate)(self._store, int(input_ptr))
            cast(Any, deallocate)(self._store, int(output_ptr))

        return result


def _execute_sandboxed_plugin_inline(wasm_path: str, stage_input: dict[str, Any]) -> dict[str, Any]:
    host = WASMPluginHost(wasm_path)
    return host.run_detector(stage_input)


def execute_sandboxed_plugin(
    wasm_path: str,
    stage_input: dict[str, Any],
    *,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """Run a WASM verifier behind a process-level budget wall."""
    from src.execution.active_manifest import ActiveExecutionBudget, get_active_manifest
    from src.execution.isolated import run_callable_isolated

    manifest = get_active_manifest("wasm_verifier")
    if timeout_seconds is not None:
        manifest = manifest.with_timeout(timeout_seconds)
    else:
        manifest = manifest.with_timeout(ActiveExecutionBudget().timeout_seconds)

    result = run_callable_isolated(
        _execute_sandboxed_plugin_inline,
        (wasm_path, stage_input),
        {},
        manifest,
    )
    if not result.ok:
        return {
            "verified": False,
            "error": result.reason or "wasm_execution_failed",
            "message": result.error,
            "killed": result.killed,
            "manifest": result.manifest,
        }
    return cast(dict[str, Any], result.value)
