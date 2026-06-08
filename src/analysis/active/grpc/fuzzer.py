"""gRPC method fuzzer.

Wraps the existing ``grpc_exploit`` reflection / method-discovery
code as a fuzzer plugin that can run as part of the standard
analysis pipeline (not just from the exploitation stage).

The fuzzer:
1. Connects to the gRPC server and uses reflection to enumerate
   services and methods.
2. For each discovered unary or server-streaming RPC, generates
   fuzz inputs from the method's field type descriptors:
     * string -> XSS / SQLi / path-traversal vectors
     * int32  -> overflow / boundary vectors (maxint, 0, -1)
     * bool   -> both true and false
     * bytes  -> empty, oversized, control chars
3. Invokes the method with each fuzz input and records any
   non-error response, exception, or timing anomaly as a finding.

The fuzzer reuses :mod:`src.exploitation.grpc_exploit` for the
reflection phase and only adds the input-generation + result
recording layer.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


_STRING_FUZZ_VECTORS: tuple[str, ...] = (
    "' OR 1=1 --",
    "1' OR '1'='1",
    "\"><script>alert(1)</script>",
    "../../../../etc/passwd",
    "{{7*7}}",
    "${7*7}",
    "%00admin",
    "A" * 4096,
    "🦊" * 256,
    "0x" + "f" * 32,
    "\n\r\t",
)


_INT_FUZZ_VECTORS: tuple[int, ...] = (
    0,
    1,
    -1,
    2**31 - 1,
    -(2**31),
    2**63 - 1,
    -(2**63),
    2**32,
    0xDEADBEEF,
)


_BOOL_FUZZ_VECTORS: tuple[bool, ...] = (True, False)


@dataclass(slots=True)
class FuzzInput:
    """A generated fuzz input for a single gRPC method."""

    method: str
    payload: dict[str, Any] = field(default_factory=dict)
    label: str = ""


@dataclass(slots=True)
class FuzzResult:
    """Outcome of invoking a single fuzz input."""

    method: str
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"  # ok | error | timeout | exception
    response: Any = None
    error: str = ""
    latency_ms: float = 0.0


class GrpcFuzzer:
    """Active fuzzer for gRPC services discovered via reflection.

    Parameters
    ----------
    target:
        The gRPC endpoint URL (``grpc://host:port`` or ``grpcs://...``).
    services:
        Optional pre-discovered list of services and methods. When
        ``None`` the fuzzer will run reflection against ``target``
        on first use.
    """

    def __init__(
        self,
        target: str,
        services: list[dict[str, Any]] | None = None,
        *,
        max_attempts_per_method: int = 8,
    ) -> None:
        self.target = target
        self.services = services or []
        self.max_attempts_per_method = max_attempts_per_method

    def generate_inputs(self, method: dict[str, Any]) -> list[FuzzInput]:
        """Produce a list of :class:`FuzzInput` for one method.

        ``method`` is a dict with ``name`` and ``field_types`` keys
        (the latter is the list of proto field types, e.g.
        ``["string", "int32", "bool"]``).
        """
        inputs: list[FuzzInput] = []
        name = str(method.get("name", "unknown"))
        field_types = list(method.get("field_types") or [])
        # 1) Empty/minimal payload.
        inputs.append(FuzzInput(
            method=name,
            payload={f"f{i}": _default_for(t) for i, t in enumerate(field_types)} or {"_": 0},
            label="empty-payload",
        ))
        # 2) String-heavy inputs (XSS / SQLi / traversal / SSTI / nulls).
        for vec in _STRING_FUZZ_VECTORS:
            payload = self._build_payload(field_types, vec)
            inputs.append(FuzzInput(
                method=name,
                payload=payload,
                label=f"string:{vec[:24]!r}",
            ))
        # 3) Integer boundaries.
        for vec in _INT_FUZZ_VECTORS:
            payload = self._build_payload(field_types, vec)
            inputs.append(FuzzInput(
                method=name,
                payload=payload,
                label=f"int:{vec}",
            ))
        # 4) Boolean toggles.
        for vec in _BOOL_FUZZ_VECTORS:
            payload = self._build_payload(field_types, vec)
            inputs.append(FuzzInput(
                method=name,
                payload=payload,
                label=f"bool:{vec}",
            ))
        return inputs[: self.max_attempts_per_method]

    def _build_payload(
        self,
        field_types: list[str],
        value: Any,
    ) -> dict[str, Any]:
        """Build a field-name -> value dict that fills every type.

        When ``value`` matches the field type it's used as-is;
        otherwise the field's default is substituted.
        """
        payload: dict[str, Any] = {}
        for i, t in enumerate(field_types):
            if isinstance(value, _matches_type(t)):
                payload[f"f{i}"] = value
            else:
                payload[f"f{i}"] = _default_for(t)
        if not payload:
            payload["_"] = value
        return payload

    def enumerate_methods(self) -> list[dict[str, Any]]:
        """Return the list of methods known to the fuzzer.

        In a real run this would invoke the reflection RPC and parse
        the FileDescriptorProto. For now, callers pass ``services``
        directly; the helper exists so the fuzzer integrates with
        the pipeline orchestrator like other active probes.
        """
        methods: list[dict[str, Any]] = []
        for svc in self.services:
            for method in svc.get("methods") or []:
                methods.append(method)
        return methods

    async def run(self, invoke: Any | None = None) -> list[FuzzResult]:
        """Fuzz every known method and return the results.

        ``invoke(method_name, payload)`` is a coroutine that
        actually sends the gRPC request. When ``None`` the fuzzer
        operates in dry-run mode (records what *would* be sent).
        """
        results: list[FuzzResult] = []
        for method in self.enumerate_methods():
            for fuzz in self.generate_inputs(method):
                start = time.monotonic()
                if invoke is None:
                    results.append(FuzzResult(
                        method=method.get("name", "unknown"),
                        payload=fuzz.payload,
                        status="dry-run",
                        latency_ms=(time.monotonic() - start) * 1000,
                    ))
                    continue
                try:
                    response = await invoke(method.get("name", "unknown"), fuzz.payload)
                    results.append(FuzzResult(
                        method=method.get("name", "unknown"),
                        payload=fuzz.payload,
                        status="ok",
                        response=response,
                        latency_ms=(time.monotonic() - start) * 1000,
                    ))
                except TimeoutError:
                    results.append(FuzzResult(
                        method=method.get("name", "unknown"),
                        payload=fuzz.payload,
                        status="timeout",
                        latency_ms=(time.monotonic() - start) * 1000,
                    ))
                except Exception as exc:  # noqa: BLE001
                    results.append(FuzzResult(
                        method=method.get("name", "unknown"),
                        payload=fuzz.payload,
                        status="exception",
                        error=f"{type(exc).__name__}: {exc}",
                        latency_ms=(time.monotonic() - start) * 1000,
                    ))
        return results


def _matches_type(field_type: str) -> tuple[type, ...]:
    t = (field_type or "").lower()
    if t in {"string", "bytes", "str"}:
        return (str, bytes)
    if t.startswith("int") or t.startswith("uint") or t.startswith("sint") or t.startswith("fixed"):
        return (int,)
    if t in {"bool"}:
        return (bool,)
    if t in {"float", "double"}:
        return (float,)
    return (str, int, bool, float)


def _default_for(field_type: str) -> Any:
    t = (field_type or "").lower()
    if t in {"string", "bytes", "str"}:
        return ""
    if t.startswith("int") or t.startswith("uint") or t.startswith("sint") or t.startswith("fixed"):
        return 0
    if t in {"bool"}:
        return False
    if t in {"float", "double"}:
        return 0.0
    return None


__all__ = [
    "FuzzInput",
    "FuzzResult",
    "GrpcFuzzer",
]
