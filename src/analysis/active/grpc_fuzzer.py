"""gRPC method fuzzer plugin.

Wraps the reflection-based enumeration in
:mod:`src.exploitation.grpc_exploit` with a systematic fuzzer that
generates typed inputs for every discovered unary / server-streaming
RPC.

Fuzz vectors are derived from the protobuf field types reported by
the descriptor:

* ``string``  → XSS / SQLi / path-traversal / format-string vectors
* ``bytes``   → null bytes, oversized payloads
* ``int32``/``int64`` → boundary values (0, MAX, MIN, -1) and overflow
* ``bool``    → true / false to test auth bypass
* ``enum``    → 0, 1, 2, MAX — finds undocumented enum values
* ``message`` → nested fuzz of every field recursively
* ``repeated`` → 0, 1, 1000 elements to test for unbounded growth

The fuzzer is intentionally light: it does not mutate byte
sequences with AFL-style coverage feedback. It produces a
:class:`GrpcFuzzerResult` for each RPC that includes the count of
unique error codes, the number of requests that produced a 5xx, and
the slowest response — all of which are leading indicators of a
useful vulnerability.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


# Strings commonly used to trigger XSS / SQLi / SSTI in any string
# field. Kept conservative to avoid noisy probes; WAF evasion is
# applied separately by the WAF-aware adapter.
DEFAULT_STRING_VECTORS: tuple[str, ...] = (
    "",
    "A" * 4096,
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "{{7*7}}",
    "../../../etc/passwd",
    "file:///etc/passwd",
    "%s%s%s%s%s",
    "null",
    "\\x00",
    "0xCAFEBABE",
    "true",
    "[]",
    "{}",
)

# Boundary values for int32 / int64 fuzzing.
INT_BOUNDARY_VALUES: tuple[int, ...] = (
    0,
    1,
    -1,
    2**31 - 1,
    -(2**31),
    2**32 - 1,
    2**63 - 1,
    -(2**63),
)


@dataclass
class GrpcMethod:
    """A single RPC method description."""

    service: str
    name: str
    full_name: str
    client_streaming: bool = False
    server_streaming: bool = False
    input_fields: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class GrpcFuzzerResult:
    """Fuzzer output for a single RPC method."""

    service: str
    method: str
    request_count: int
    unique_status_codes: list[int]
    five_xx_count: int
    slowest_ms: float
    fastest_ms: float
    findings: list[dict[str, Any]] = field(default_factory=list)
    sample_errors: list[str] = field(default_factory=list)

    def to_finding(self) -> dict[str, Any]:
        return {
            "type": "grpc_fuzz",
            "title": f"gRPC method {self.service}/{self.method} fuzzed",
            "severity": (
                "high"
                if self.five_xx_count > 5 or self.slowest_ms > 5000
                else "medium"
                if self.five_xx_count > 0
                else "low"
            ),
            "description": (
                f"Fuzzed {self.request_count} payloads against "
                f"{self.service}/{self.method}. Status codes: "
                f"{self.unique_status_codes}; 5xx: {self.five_xx_count}; "
                f"slowest: {self.slowest_ms:.0f}ms; fastest: "
                f"{self.fastest_ms:.0f}ms."
            ),
            "evidence": {
                "service": self.service,
                "method": self.method,
                "request_count": self.request_count,
                "unique_status_codes": self.unique_status_codes,
                "five_xx_count": self.five_xx_count,
                "slowest_ms": self.slowest_ms,
                "fastest_ms": self.fastest_ms,
                "findings": self.findings,
                "sample_errors": self.sample_errors[:5],
            },
        }


def _build_fuzz_value(field: Mapping[str, Any]) -> list[Any]:
    """Return a list of fuzz values for a single protobuf field.

    The fuzzer picks 1-2 vectors per field type so the total request
    count stays bounded for large schemas.
    """
    ftype = (field.get("type") or field.get("kind") or "").lower()
    field.get("name", "field")
    is_repeated = bool(field.get("label") == "repeated" or field.get("repeated"))
    values: list[Any] = []
    if ftype in {"string", "bytes"}:
        values.extend(DEFAULT_STRING_VECTORS[:6])
    elif ftype in {"int32", "int64", "uint32", "uint64", "sint32", "sint64"}:
        values.extend(INT_BOUNDARY_VALUES[:6])
    elif ftype in {"bool"}:
        values.extend([True, False])
    elif ftype in {"enum"}:
        values.extend([0, 1, 2, 99])
    elif ftype in {"double", "float"}:
        values.extend([0.0, 1.0, -1.0, 1e308, -1e308, float("inf"), float("nan")])
    elif ftype in {"message", "group"}:
        # Recursively fuzz a few sub-fields. The recursion is
        # bounded to avoid exponential blow-up.
        sub_fields = field.get("fields", [])
        for sub in sub_fields[:3]:
            for sub_value in _build_fuzz_value(sub):
                values.append({sub["name"]: sub_value})
    else:
        # Unknown type: pass an empty payload and let the server
        # respond with the canonical "missing field" error.
        values.append(None)
    if is_repeated:
        # Wrap each scalar value in a list and add an empty / large
        # list variant to test unbounded growth.
        return [v if isinstance(v, list) else [v] for v in values] + [[], [None] * 1000]
    return values


def build_fuzz_messages(
    input_fields: Iterable[Mapping[str, Any]],
    *,
    max_messages: int = 32,
) -> list[dict[str, Any]]:
    """Generate up to ``max_messages`` JSON-shape payloads.

    The payloads are JSON (not raw protobuf) so the same vector
    set can be replayed against a gRPC-Web endpoint via plain
    ``application/json``. Real protobuf encoding is handled by the
    caller's transport.
    """
    out: list[dict[str, Any]] = []
    for field in list(input_fields)[:8]:
        for value in _build_fuzz_value(field):
            out.append({field.get("name", "f"): value})
            if len(out) >= max_messages:
                return out
    return out


@dataclass
class GrpcFuzzer:
    """Systematic fuzzer for gRPC methods.

    The fuzzer accepts a list of :class:`GrpcMethod` (which the
    caller produces from a reflection or .proto file parse) and an
    HTTP endpoint, then issues one POST per fuzz message. The
    transport is plain HTTP/1.1 + JSON so the fuzzer works
    against gRPC-Web endpoints and reflection-bypassing
    fallbacks.
    """

    endpoint: str
    methods: list[GrpcMethod]
    headers: Mapping[str, str] | None = None
    timeout: float = 10.0
    verify_ssl: bool = True
    max_messages_per_method: int = 32
    client: httpx.Client | None = None
    _owns_client: bool = False

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = httpx.Client(
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=dict(self.headers or {}),
            )
            self._owns_client = True

    def close(self) -> None:
        if self._owns_client and self.client is not None:
            self.client.close()

    def __enter__(self) -> GrpcFuzzer:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def run(self) -> list[GrpcFuzzerResult]:
        results: list[GrpcFuzzerResult] = []
        for method in self.methods:
            results.append(self._fuzz_method(method))
        return results

    def _fuzz_method(self, method: GrpcMethod) -> GrpcFuzzerResult:
        messages = build_fuzz_messages(
            method.input_fields, max_messages=self.max_messages_per_method
        )
        status_codes: set[int] = set()
        five_xx = 0
        slowest = 0.0
        fastest = float("inf")
        findings: list[dict[str, Any]] = []
        sample_errors: list[str] = []
        url = self._build_method_url(method)
        for message in messages:
            payload = {
                "method": method.full_name,
                "message": message,
            }
            try:
                start = time.monotonic()
                assert self.client is not None
                response = self.client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                elapsed = (time.monotonic() - start) * 1000.0
            except Exception as exc:
                logger.debug(
                    "GrpcFuzzer: %s/%s raised: %s",
                    method.service,
                    method.name,
                    exc,
                )
                continue
            status_codes.add(response.status_code)
            if 500 <= response.status_code < 600:
                five_xx += 1
                findings.append(
                    {
                        "message": message,
                        "status": response.status_code,
                        "body_preview": response.text[:300],
                    }
                )
            if elapsed > slowest:
                slowest = elapsed
            if elapsed < fastest:
                fastest = elapsed
            try:
                err_body = response.json()
                err_str = json.dumps(err_body)[:200]
            except Exception:
                err_str = response.text[:200]
            if err_str and err_str not in sample_errors:
                sample_errors.append(err_str)
        if fastest == float("inf"):
            fastest = 0.0
        return GrpcFuzzerResult(
            service=method.service,
            method=method.name,
            request_count=len(messages),
            unique_status_codes=sorted(status_codes),
            five_xx_count=five_xx,
            slowest_ms=slowest,
            fastest_ms=fastest,
            findings=findings,
            sample_errors=sample_errors,
        )

    def _build_method_url(self, method: GrpcMethod) -> str:
        parsed = urlparse(self.endpoint)
        # gRPC-Web conventionally mounts the service at /<package>.<Service>/<Method>
        # The endpoint passed in is typically the service root (e.g. https://target/grpc).
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}/{method.full_name}"


async def run_async(
    endpoint: str,
    methods: list[GrpcMethod],
    *,
    max_concurrent: int = 4,
) -> list[GrpcFuzzerResult]:
    """Asynchronous wrapper around :class:`GrpcFuzzer` for the pipeline.

    Uses ``asyncio.gather`` to fuzz several methods in parallel.
    """
    sem = asyncio.Semaphore(max_concurrent)

    async def _fuzz_one(method: GrpcMethod) -> GrpcFuzzerResult:
        async with sem:
            fuzzer = GrpcFuzzer(
                endpoint=endpoint,
                methods=[method],
                max_messages_per_method=16,
            )
            try:
                return fuzzer._fuzz_method(method)
            finally:
                fuzzer.close()

    return list(await asyncio.gather(*[_fuzz_one(m) for m in methods]))


__all__ = [
    "GrpcFuzzer",
    "GrpcFuzzerResult",
    "GrpcMethod",
    "build_fuzz_messages",
    "run_async",
]
