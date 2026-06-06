"""WebAssembly module introspector.

Parses the structure of ``*.wasm`` binaries in pure Python to surface
potentially dangerous imports, exports, and custom sections. The output is
fed into the exploitation layer so the engine selection can promote a
generic finding into a Wasm-aware probe (e.g. shared-memory gadgets).

The introspector is intentionally conservative: it reads the binary header
and section table but does not validate code or perform full decoding. It
fails closed — when parsing fails it returns an empty result and logs at
debug level so the parent detection loop is not disturbed.
"""

from __future__ import annotations

import logging
import re
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_WASM_MAGIC = b"\x00asm"
_SUPPORTED_VERSION = 1

_SECTION_TYPES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}

# Hosts/imports that we consider sensitive
_SENSITIVE_IMPORTS = {
    "wasi_snapshot_preview1",
    "wasi_unstable",
    "env",
    "js",
    "spectest",
}

# Imports often used as exfiltration sinks
_HIGH_RISK_NAMES = {
    "fd_write",
    "fd_read",
    "proc_exit",
    "sock_send",
    "sock_recv",
    "clock_time_get",
    "random_get",
    "environ_sizes_get",
    "environ_get",
    "args_sizes_get",
    "args_get",
    "path_open",
    "path_filestat_get",
}

# Exports often used to interact with the host
_HIGH_RISK_EXPORTS = {
    "malloc",
    "free",
    "alloc",
    "dealloc",
    "allocate",
    "deallocate",
    "run",
    "main",
    "init",
    "execute",
    "process",
    "render",
    "compute",
    "evaluate",
    "fuzz",
    "parse",
    "load",
    "store",
}

_URL_HINT = re.compile(r"\.wasm(\?|$|#)", re.IGNORECASE)


@dataclass(slots=True)
class WasmSection:
    section_id: int
    name: str
    size: int
    payload: bytes
    payload_offset: int


@dataclass(slots=True)
class WasmImport:
    module: str
    name: str
    kind: str
    index: int

    @property
    def is_high_risk(self) -> bool:
        return self.name in _HIGH_RISK_NAMES and self.module in _SENSITIVE_IMPORTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "name": self.name,
            "kind": self.kind,
            "index": self.index,
            "is_high_risk": self.is_high_risk,
        }


@dataclass(slots=True)
class WasmExport:
    name: str
    kind: str
    index: int

    @property
    def is_high_risk(self) -> bool:
        return self.name in _HIGH_RISK_EXPORTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "index": self.index,
            "is_high_risk": self.is_high_risk,
        }


@dataclass(slots=True)
class WasmIntrospection:
    url: str
    size: int
    version: int | None
    sections: list[WasmSection] = field(default_factory=list)
    imports: list[WasmImport] = field(default_factory=list)
    exports: list[WasmExport] = field(default_factory=list)
    has_memory: bool = False
    has_table: bool = False
    has_start: bool = False
    has_data_count: bool = False
    custom_names: list[str] = field(default_factory=list)
    parse_error: str | None = None
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "size": self.size,
            "version": self.version,
            "section_types": [s.name for s in self.sections],
            "imports": [i.to_dict() for i in self.imports],
            "exports": [e.to_dict() for e in self.exports],
            "has_memory": self.has_memory,
            "has_table": self.has_table,
            "has_start": self.has_start,
            "has_data_count": self.has_data_count,
            "custom_names": self.custom_names,
            "parse_error": self.parse_error,
            "risk_score": round(self.risk_score, 3),
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_wasm_url(url: str) -> bool:
    return bool(_URL_HINT.search(url or ""))


def is_wasm_bytes(data: bytes) -> bool:
    return bool(data) and data[:4] == _WASM_MAGIC


def introspect_bytes(data: bytes, *, url: str = "") -> WasmIntrospection:
    """Parse the top-level structure of a Wasm module."""

    result = WasmIntrospection(url=url, size=len(data), version=None)
    if not data:
        result.parse_error = "empty"
        return result
    if data[:4] != _WASM_MAGIC:
        result.parse_error = "missing_magic"
        return result
    if len(data) < 8:
        result.parse_error = "truncated_header"
        return result
    version = struct.unpack("<I", data[4:8])[0]
    result.version = version
    if version != _SUPPORTED_VERSION:
        result.parse_error = f"unsupported_version:{version}"
        # Continue parsing — defensive

    cursor = 8
    while cursor < len(data):
        section_id = data[cursor]
        cursor += 1
        size, consumed = _decode_leb128(data, cursor)
        if size is None:
            result.parse_error = f"truncated_section_at:{cursor}"
            return _finalize(result)
        cursor = consumed
        end = cursor + size
        if end > len(data):
            result.parse_error = f"section_overflow:{section_id}"
            return _finalize(result)
        payload = data[cursor:end]
        section = WasmSection(
            section_id=section_id,
            name=_SECTION_TYPES.get(section_id, f"unknown_{section_id}"),
            size=size,
            payload=payload,
            payload_offset=cursor,
        )
        result.sections.append(section)
        cursor = end

        try:
            if section_id == 7:  # export
                _parse_export_section(payload, result)
            elif section_id == 2:  # import
                _parse_import_section(payload, result)
            elif section_id == 5:  # memory
                result.has_memory = True
            elif section_id == 4:  # table
                result.has_table = True
            elif section_id == 8:  # start
                result.has_start = True
            elif section_id == 12:  # data_count
                result.has_data_count = True
            elif section_id == 0:  # custom
                _parse_custom_section(payload, result)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Section %s parse failed for %s: %s", section.name, url, exc)

    return _finalize(result)


def introspect_url_candidate(url: str, body: bytes | None = None) -> dict[str, Any]:
    """Best-effort introspection for a URL — returns a small summary dict.

    If ``body`` is provided and is Wasm, the bytes are introspected.
    Otherwise we just mark the URL as a Wasm candidate and return a
    low-confidence indicator.
    """

    if body is not None and is_wasm_bytes(body):
        return introspect_bytes(body, url=url).to_dict()
    if is_wasm_url(url):
        return {
            "url": url,
            "is_wasm_url": True,
            "risk_score": 0.10,
            "indicator": "wasm_url_candidate",
        }
    return {
        "url": url,
        "is_wasm_url": False,
        "risk_score": 0.0,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_leb128(data: bytes, offset: int) -> tuple[int | None, int]:
    result = 0
    shift = 0
    cursor = offset
    while cursor < len(data):
        byte = data[cursor]
        result |= (byte & 0x7F) << shift
        cursor += 1
        if (byte & 0x80) == 0:
            return result, cursor
        shift += 7
        if shift > 63:
            return None, cursor
    return None, cursor


def _decode_name(data: bytes, offset: int) -> tuple[str | None, int]:
    length, consumed = _decode_leb128(data, offset)
    if length is None or consumed + length > len(data):
        return None, consumed
    try:
        name = data[consumed : consumed + length].decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        name = None
    return name, consumed + length


def _parse_import_section(payload: bytes, result: WasmIntrospection) -> None:
    cursor = 0
    count, cursor = _decode_leb128(payload, cursor)
    if count is None:
        return
    for _ in range(count):
        module, cursor = _decode_name(payload, cursor)
        if module is None:
            return
        name, cursor = _decode_name(payload, cursor)
        if name is None:
            return
        if cursor >= len(payload):
            return
        kind_byte = payload[cursor]
        cursor += 1
        kind_label = {0: "func", 1: "table", 2: "memory", 3: "global"}.get(kind_byte, f"kind_{kind_byte}")
        # Skip the kind-specific payload by jumping past the next LEB128.
        if kind_byte == 0:  # func — type index
            _, cursor = _decode_leb128(payload, cursor)
        elif kind_byte == 1:  # table
            cursor = _skip_table_type(payload, cursor)
        elif kind_byte == 2:  # memory
            cursor = _skip_memory_type(payload, cursor)
        elif kind_byte == 3:  # global
            cursor = _skip_global_type(payload, cursor)
        result.imports.append(
            WasmImport(module=module, name=name, kind=kind_label, index=len(result.imports))
        )


def _parse_export_section(payload: bytes, result: WasmIntrospection) -> None:
    cursor = 0
    count, cursor = _decode_leb128(payload, cursor)
    if count is None:
        return
    for _ in range(count):
        name, cursor = _decode_name(payload, cursor)
        if name is None:
            return
        if cursor >= len(payload):
            return
        kind_byte = payload[cursor]
        cursor += 1
        kind_label = {0: "func", 1: "table", 2: "memory", 3: "global"}.get(kind_byte, f"kind_{kind_byte}")
        _, cursor = _decode_leb128(payload, cursor)
        result.exports.append(
            WasmExport(name=name, kind=kind_label, index=len(result.exports))
        )


def _parse_custom_section(payload: bytes, result: WasmIntrospection) -> None:
    cursor = 0
    name, cursor = _decode_name(payload, cursor)
    if name:
        result.custom_names.append(name)


def _skip_table_type(payload: bytes, cursor: int) -> int:
    if cursor >= len(payload):
        return cursor
    cursor += 1  # reference type
    cursor += 1  # limits flag
    _, cursor = _decode_leb128(payload, cursor)
    return cursor


def _skip_memory_type(payload: bytes, cursor: int) -> int:
    if cursor >= len(payload):
        return cursor
    cursor += 1  # limits flag
    _, cursor = _decode_leb128(payload, cursor)
    return cursor


def _skip_global_type(payload: bytes, cursor: int) -> int:
    if cursor + 1 >= len(payload):
        return cursor
    cursor += 2  # value type + mutability
    # Skip init expression: block_type byte (0x40) + end (0x0B)
    cursor += 2
    return cursor


def _finalize(result: WasmIntrospection) -> WasmIntrospection:
    high_risk_imports = sum(1 for i in result.imports if i.is_high_risk)
    high_risk_exports = sum(1 for e in result.exports if e.is_high_risk)
    score = 0.0
    if result.has_memory:
        score += 0.10
    if result.has_table:
        score += 0.05
    if result.has_start:
        score += 0.05
    if result.has_data_count:
        score += 0.10
    if result.imports:
        score += min(0.20, 0.05 * len(result.imports))
    if high_risk_imports:
        score += min(0.40, 0.20 * high_risk_imports)
    if high_risk_exports:
        score += min(0.30, 0.10 * high_risk_exports)
    if result.parse_error:
        score *= 0.5
    result.risk_score = min(0.99, max(0.0, score))
    return result


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def findings_from_introspection(
    introspection: WasmIntrospection,
) -> list[dict[str, Any]]:
    """Convert a ``WasmIntrospection`` into detection finding dicts."""

    findings: list[dict[str, Any]] = []
    for imp in introspection.imports:
        if not imp.is_high_risk:
            continue
        findings.append(
            {
                "url": introspection.url,
                "indicator": "wasm_high_risk_import",
                "summary": f"Wasm module imports high-risk function {imp.module}::{imp.name}",
                "severity": "medium",
                "confidence": 0.65,
                "module": imp.module,
                "import": imp.name,
                "kind": imp.kind,
            }
        )
    for exp in introspection.exports:
        if not exp.is_high_risk:
            continue
        findings.append(
            {
                "url": introspection.url,
                "indicator": "wasm_high_risk_export",
                "summary": f"Wasm module exports potentially abusable function {exp.name}",
                "severity": "low",
                "confidence": 0.50,
                "export": exp.name,
                "kind": exp.kind,
            }
        )
    if introspection.risk_score >= 0.6 and not findings:
        findings.append(
            {
                "url": introspection.url,
                "indicator": "wasm_risk_score",
                "summary": "Wasm module exhibits elevated risk profile",
                "severity": "low",
                "confidence": round(introspection.risk_score, 3),
                "risk_score": round(introspection.risk_score, 3),
            }
        )
    return findings


def batch_introspect(
    candidates: Iterable[tuple[str, bytes | None]],
) -> list[dict[str, Any]]:
    """Introspect a batch of (url, body) candidates and return findings."""

    findings: list[dict[str, Any]] = []
    for url, body in candidates:
        if body is not None and is_wasm_bytes(body):
            intro = introspect_bytes(body, url=url)
            findings.extend(findings_from_introspection(intro))
        elif is_wasm_url(url):
            findings.append(
                {
                    "url": url,
                    "indicator": "wasm_url_candidate",
                    "summary": "URL appears to reference a Wasm binary (no body sampled)",
                    "severity": "info",
                    "confidence": 0.30,
                }
            )
    return findings


__all__ = [
    "WasmIntrospection",
    "WasmImport",
    "WasmExport",
    "WasmSection",
    "batch_introspect",
    "findings_from_introspection",
    "introspect_bytes",
    "introspect_url_candidate",
    "is_wasm_bytes",
    "is_wasm_url",
]
