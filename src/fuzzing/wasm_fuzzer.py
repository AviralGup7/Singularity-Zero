"""WASM (WebAssembly) attack surface fuzzer.

Tests for vulnerabilities in WASM module loading, memory corruption,
and JS-to-WASM boundary issues. Supports module structure mutation,
import injection, and memory abuse.
"""

from __future__ import annotations

import logging
import random
import struct
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check

logger = logging.getLogger(__name__)

# WASM magic bytes and version
WASM_MAGIC: bytes = b"\x00asm"
WASM_VERSION: bytes = b"\x01\x00\x00\x00"

# WASM section IDs
WASM_SECTION_CUSTOM: int = 0
WASM_SECTION_TYPE: int = 1
WASM_SECTION_IMPORT: int = 2
WASM_SECTION_FUNCTION: int = 3
WASM_SECTION_TABLE: int = 4
WASM_SECTION_MEMORY: int = 5
WASM_SECTION_GLOBAL: int = 6
WASM_SECTION_EXPORT: int = 7
WASM_SECTION_START: int = 8
WASM_SECTION_ELEMENT: int = 9
WASM_SECTION_CODE: int = 10
WASM_SECTION_DATA: int = 11


def _build_wasm_section(section_id: int, content: bytes) -> bytes:
    """Build a WASM section (id + length-prefixed content)."""
    length = len(content)
    # LEB128-encode the length
    leb = bytearray()
    remaining = length
    while remaining > 0:
        byte_val = remaining & 0x7F
        remaining >>= 7
        if remaining > 0:
            byte_val |= 0x80
        leb.append(byte_val)
    return bytes([section_id]) + bytes(leb) + content


def _build_minimal_wasm_module() -> bytes:
    """Build a minimal valid WASM module with a single function.

    The module exports a single function 'test' that returns i32(42).
    Useful as a baseline for fuzzing.
    """
    module = bytearray(WASM_MAGIC + WASM_VERSION)

    # Type section: one function type (nil -> i32)
    type_section = struct.pack("<B", 0x60)  # functype
    type_section += struct.pack("<B", 0)  # no params
    type_section += struct.pack("<B", 1)  # 1 return
    type_section += struct.pack("<B", 0x7F)  # i32
    type_section = struct.pack("<B", 1) + type_section  # 1 type
    module += _build_wasm_section(WASM_SECTION_TYPE, type_section)

    # Function section: one function (type index 0)
    func_section = struct.pack("<B", 0)  # type index 0
    func_section = struct.pack("<B", 1) + func_section  # 1 function
    module += _build_wasm_section(WASM_SECTION_FUNCTION, func_section)

    # Export section: export the function as "test"
    name = b"test"
    export_section = struct.pack("<B", 1)  # 1 export
    export_section += struct.pack("<B", len(name)) + name
    export_section += struct.pack("<B", 0)  # func export
    export_section += struct.pack("<B", 0)  # func index 0
    module += _build_wasm_section(WASM_SECTION_EXPORT, export_section)

    # Code section: function body (return i32.const 42)
    body = b"\x00"  # no locals
    body += b"\x41\x2a"  # i32.const 42
    body += b"\x0b"  # end
    body = struct.pack("<B", len(body)) + body
    code_section = struct.pack("<B", 1) + body  # 1 function body
    module += _build_wasm_section(WASM_SECTION_CODE, code_section)

    return bytes(module)


def _build_corrupted_wasm_module(corruption_type: str = "truncated") -> bytes:
    """Generate a malformed WASM module for fuzzing."""
    base = _build_minimal_wasm_module()

    if corruption_type == "truncated":
        return base[: random.randint(4, len(base) - 1)]  # noqa: S311
    elif corruption_type == "magic":
        return b"\x00\x00\x00\x00" + WASM_VERSION + base[8:]
    elif corruption_type == "version":
        return WASM_MAGIC + b"\xff\xff\xff\xff" + base[8:]
    elif corruption_type == "oversized_section":
        # Valid header + single section with impossible length
        section_id = WASM_SECTION_CUSTOM
        fake_len = struct.pack("<I", 0xFFFFFFFF)[:4]
        return WASM_MAGIC + WASM_VERSION + bytes([section_id]) + fake_len + b"A" * 64
    elif corruption_type == "invalid_opcode":
        # Replace the bytecode body with invalid opcodes
        body = b"\x00" + b"\xff" * 10 + b"\x0b"
        body = struct.pack("<B", len(body)) + body
        code_section = struct.pack("<B", 1) + body
        section = _build_wasm_section(WASM_SECTION_CODE, code_section)
        return WASM_MAGIC + WASM_VERSION + section
    return base


def _build_wasm_memory_abuse_module() -> bytes:
    """Build a WASM module that tests memory limits.

    Creates a module with a large memory initial size to test
    for OOM conditions or memory corruption.
    """
    module = bytearray(WASM_MAGIC + WASM_VERSION)

    # Type section: one function type (nil -> nil)
    type_section = struct.pack("<B", 0x60)  # functype
    type_section += struct.pack("<B", 0)  # no params
    type_section += struct.pack("<B", 0)  # no returns
    type_section = struct.pack("<B", 1) + type_section
    module += _build_wasm_section(WASM_SECTION_TYPE, type_section)

    # Memory section with large initial page count
    memory_section = b"\x00"  # no limits flag? Actually need limits
    # Memory type: limits with initial = 65536 pages (4GB)
    memory_section = b"\x01" + struct.pack("<I", 0x10000)  # 65536 pages
    memory_section = struct.pack("<B", 1) + memory_section  # 1 memory
    module += _build_wasm_section(WASM_SECTION_MEMORY, memory_section)

    return bytes(module)


# WASM fuzzing payload configurations
WASM_FUZZ_PAYLOADS: list[dict[str, Any]] = [
    {
        "label": "wasm_truncated_module",
        "description": "Truncated WASM binary for parser boundary testing",
        "payload_type": "truncated",
    },
    {
        "label": "wasm_corrupted_magic",
        "description": "WASM module with corrupted magic bytes",
        "payload_type": "magic",
    },
    {
        "label": "wasm_invalid_version",
        "description": "WASM module with invalid version",
        "payload_type": "version",
    },
    {
        "label": "wasm_oversized_section",
        "description": "WASM module with oversized section length",
        "payload_type": "oversized_section",
    },
    {
        "label": "wasm_invalid_opcode",
        "description": "WASM module with invalid opcodes in body",
        "payload_type": "invalid_opcode",
    },
    {
        "label": "wasm_memory_abuse",
        "description": "WASM module requesting 4GB memory",
        "payload_type": "memory_abuse",
    },
]


async def run_wasm_fuzzing_campaign(
    url: str,
    *,
    timeout_seconds: float = 5.0,
    verify_tls: bool = True,
) -> list[dict[str, Any]]:
    """Run WASM fuzzing against a target URL.

    Sends various malformed WASM modules to the target via HTTP and
    checks for error responses indicating WASM parsing.

    Args:
        url: Target URL (expects a WASM module endpoint).
        timeout_seconds: HTTP timeout per request.
        verify_tls: Whether to verify TLS certificates. Defaults to True.

    Returns:
        List of finding dicts.
    """
    import httpx

    findings: list[dict[str, Any]] = []
    if not is_safe_url_with_dns_check(url):
        logger.warning("WASM fuzzer: URL failed safety check, skipping: %s", url)
        return findings

    endpoint_key = endpoint_signature(url)
    base_endpoint = endpoint_base_key(url)
    endpoint_type = classify_endpoint(url)

    async with httpx.AsyncClient(timeout=timeout_seconds, verify=verify_tls) as client:
        for case in WASM_FUZZ_PAYLOADS:
            label = case["label"]
            payload_type = case["payload_type"]

            if payload_type == "memory_abuse":
                wasm_bytes = _build_wasm_memory_abuse_module()
            else:
                wasm_bytes = _build_corrupted_wasm_module(payload_type)

            try:
                resp = await client.post(
                    url,
                    content=wasm_bytes,
                    headers={"Content-Type": "application/wasm"},
                )
            except Exception:
                logger.debug("WASM fuzzer: request failed for %s, skipping", url)
                continue

            if resp is None:
                continue

            body = resp.text.lower()
            wasm_indicators = [
                "compile",
                "wasm",
                "webassembly",
                "instantiate",
                "linkerror",
                "runtimeerror",
                "compilerror",
                "invalid",
                "unreachable",
                "out of memory",
            ]
            matched = [ind for ind in wasm_indicators if ind in body]

            if matched or resp.status_code in (400, 413, 422, 500):
                severity = "medium" if resp.status_code in (500, 413) else "low"
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": base_endpoint,
                        "endpoint_type": endpoint_type,
                        "issues": [f"wasm_{label}"],
                        "probe_type": "wasm_fuzzer",
                        "severity": severity,
                        "confidence": 0.5 if not matched else 0.7,
                        "evidence": {
                            "scenario": label,
                            "status_code": resp.status_code,
                            "matched_indicators": matched,
                            "response_preview": body[:200],
                        },
                    }
                )
                logger.debug(
                    "WASM fuzzer: %s matched=%s status=%d", label, matched, resp.status_code
                )

    return findings
