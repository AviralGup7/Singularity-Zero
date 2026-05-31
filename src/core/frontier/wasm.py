"""
Cyber Security Test Pipeline - WASM Plugin Sandbox
Provides a secure, isolated runtime for executing untrusted security detectors.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
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

_DEFAULT_WASM_TIMEOUT_SECONDS = 5.0
_DEFAULT_WASM_FUEL = 50_000_000
_DEFAULT_WASM_MEMORY_BYTES = 128 * 1024 * 1024
_DEFAULT_WASM_MAX_INPUT_BYTES = 1_000_000
_DEFAULT_WASM_MAX_OUTPUT_BYTES = 1_000_000
_ALLOWED_WASM_IMPORT_MODULES = {"wasi_snapshot_preview1", "wasi_unstable"}

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
            {
                "input_sha256": hashlib.sha256(
                    json.dumps(redacted_input, sort_keys=True).encode()
                ).hexdigest()
            },
        )
    except Exception:
        return


class WASMPluginHost:
    """
    Host environment for WASM-based security plugins.
    Enforces memory limits and CPU timeouts for execution.
    """

    def __init__(
        self,
        wasm_path: str,
        *,
        timeout_seconds: float = _DEFAULT_WASM_TIMEOUT_SECONDS,
        memory_limit_bytes: int = _DEFAULT_WASM_MEMORY_BYTES,
        fuel: int = _DEFAULT_WASM_FUEL,
        max_input_bytes: int = _DEFAULT_WASM_MAX_INPUT_BYTES,
        max_output_bytes: int = _DEFAULT_WASM_MAX_OUTPUT_BYTES,
    ) -> None:
        self._timeout_seconds = max(0.05, float(timeout_seconds))
        self._memory_limit_bytes = max(64 * 1024, int(memory_limit_bytes))
        self._fuel = max(1_000, int(fuel))
        self._max_input_bytes = max(1024, int(max_input_bytes))
        self._max_output_bytes = max(1024, int(max_output_bytes))

        self._engine = self._build_engine()
        self._linker = wasmtime.Linker(self._engine)
        self._linker.define_wasi()

        self._module = wasmtime.Module.from_file(self._engine, wasm_path)
        self._validate_module_imports()
        self._store = wasmtime.Store(self._engine)
        self._configure_store()
        self._store.set_wasi(self._locked_down_wasi_config())

    def _build_engine(self) -> Any:
        config_type = getattr(wasmtime, "Config", None)
        if config_type is None:
            return wasmtime.Engine()
        try:
            config = config_type()
            for name, value in (
                ("consume_fuel", True),
                ("epoch_interruption", True),
                ("debug_info", False),
                ("cache", False),
            ):
                if hasattr(config, name):
                    try:
                        setattr(config, name, value)
                    except Exception:
                        logger.debug("Failed to set wasmtime config.%s", name, exc_info=True)
            return wasmtime.Engine(config)
        except TypeError:
            return wasmtime.Engine()

    def _validate_module_imports(self) -> None:
        imports = getattr(self._module, "imports", None)
        if imports is None:
            return
        imports = imports() if callable(imports) else imports
        for item in imports or ():
            module = str(getattr(item, "module", "") or "")
            name = str(getattr(item, "name", "") or "")
            if module in _ALLOWED_WASM_IMPORT_MODULES or module.startswith("wasi:"):
                continue
            raise RuntimeError(f"WASM import '{module}.{name}' is not allowed")

    def _configure_store(self) -> None:
        set_limits = getattr(self._store, "set_limits", None)
        if callable(set_limits):
            set_limits(
                memory_size=self._memory_limit_bytes,
                table_elements=10_000,
                instances=1,
                tables=8,
                memories=1,
            )
        set_fuel = getattr(self._store, "set_fuel", None)
        if callable(set_fuel):
            try:
                set_fuel(self._fuel)
            except Exception:
                logger.debug("Failed to set WASM fuel budget", exc_info=True)
        set_epoch_deadline = getattr(self._store, "set_epoch_deadline", None)
        if callable(set_epoch_deadline):
            try:
                set_epoch_deadline(1)
            except Exception:
                logger.debug("Failed to set WASM epoch deadline", exc_info=True)

    def _locked_down_wasi_config(self) -> Any:
        config = wasmtime.WasiConfig()
        # Do not inherit argv, environment, stdio, or preopened directories.
        for name, value in (("argv", []), ("env", [])):
            if hasattr(config, name):
                try:
                    setattr(config, name, value)
                except Exception:
                    logger.debug("Failed to clear WASI %s", name, exc_info=True)
        return config

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
        if len(input_json) > self._max_input_bytes:
            raise RuntimeError(f"WASM input exceeded {self._max_input_bytes} bytes")
        input_ptr = cast(Any, allocate)(self._store, len(input_json))
        if int(input_ptr) < 0:
            raise RuntimeError("WASM allocator returned an invalid input pointer")

        # Write to WASM memory - use memory.write for efficiency
        # Fix #215: The wasmtime Python binding uses memory.write(store, data, offset)
        cast(Any, memory).write(self._store, input_json, int(input_ptr))

        # 2. Execute
        logger.info("Executing WASM Plugin...")
        start = time.monotonic()

        timer_fired = False

        def interrupt_wasm() -> None:
            nonlocal timer_fired
            timer_fired = True
            increment_epoch = getattr(self._engine, "increment_epoch", None)
            if callable(increment_epoch):
                try:
                    increment_epoch()
                except Exception:
                    logger.debug("Failed to interrupt WASM engine epoch", exc_info=True)

        watchdog_timer = threading.Timer(self._timeout_seconds, interrupt_wasm)
        watchdog_timer.daemon = True
        watchdog_timer.start()

        try:
            output_ptr = cast(Any, run)(self._store, int(input_ptr), len(input_json))
        finally:
            watchdog_timer.cancel()

        duration = time.monotonic() - start
        if timer_fired or duration > self._timeout_seconds:
            raise TimeoutError(f"WASM detector exceeded {self._timeout_seconds}s budget")

        # 3. Retrieve Output
        # (Assuming the first 4 bytes at output_ptr contain the length)
        ptr = int(output_ptr)
        if ptr < 0:
            raise RuntimeError("WASM detector returned an invalid output pointer")
        output_len_bytes = cast(Any, memory).read(self._store, ptr, ptr + 4)
        if len(output_len_bytes) != 4:
            raise RuntimeError("WASM detector returned a truncated output length")
        output_len = int.from_bytes(output_len_bytes, "little")

        if output_len == 0:
            return {"verified": False, "error": "empty_output"}
        if output_len > self._max_output_bytes:
            raise RuntimeError(f"WASM output exceeded {self._max_output_bytes} bytes")

        output_json_bytes = cast(Any, memory).read(self._store, ptr + 4, ptr + 4 + output_len)
        output_json = output_json_bytes.decode()

        decoded = json.loads(output_json)
        if not isinstance(decoded, dict):
            raise RuntimeError("WASM detector returned non-object JSON")
        result = cast(dict[str, Any], decoded)
        result["_wasm_duration"] = duration

        # 4. Cleanup
        if deallocate and isinstance(deallocate, wasmtime.Func):
            cast(Any, deallocate)(self._store, int(input_ptr))
            cast(Any, deallocate)(self._store, int(output_ptr))

        return result


def _execute_sandboxed_plugin_inline(
    wasm_path: str,
    stage_input: dict[str, Any],
    timeout_seconds: float,
    max_output_bytes: int,
) -> dict[str, Any]:
    host = WASMPluginHost(
        wasm_path,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
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

    budget = manifest.budget.normalized()

    result = run_callable_isolated(
        _execute_sandboxed_plugin_inline,
        (wasm_path, stage_input, budget.timeout_seconds, budget.max_output_bytes),
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
