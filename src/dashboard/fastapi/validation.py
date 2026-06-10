"""Input validation utilities shared across dashboard APIs."""

import ipaddress
import json
import logging
import os
import re
import socket
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,254}$")
_VALID_RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,509}$")
_REPLAY_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
_ALLOWED_URL_SCHEMES = {"http", "https"}
_MAX_JSON_SIZE = 1_048_576
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".corp")
_CLOUD_METADATA_IP = "169.254.169.254"


def _has_dangerous_chars(value: str) -> bool:
    if "\x00" in value:
        return True
    if any(ord(ch) < 0x20 and ch not in ("\t", "\n", "\r") for ch in value):
        return True
    return False


def _is_path_traversal(value: str) -> bool:
    segments = value.replace("\\", "/").split("/")
    return ".." in segments


def validate_target_name(name: str) -> bool:
    if not name:
        return False
    if _has_dangerous_chars(name) or _is_path_traversal(name):
        return False
    return bool(_VALID_NAME_RE.match(name))


def validate_run_name(name: str) -> bool:
    if not name:
        return False
    if _has_dangerous_chars(name) or _is_path_traversal(name):
        return False
    return bool(_VALID_RUN_RE.match(name))


def validate_replay_id(replay_id: str) -> bool:
    if not replay_id:
        return False
    if _has_dangerous_chars(replay_id) or _is_path_traversal(replay_id):
        return False
    return bool(_REPLAY_ID_RE.match(replay_id))


def validate_url(url: str) -> bool:
    if not url:
        return False
    if _has_dangerous_chars(url):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in _ALLOWED_URL_SCHEMES:
        return False
    if not parsed.hostname:
        return False
    # Check for path traversal in both raw and percent-decoded forms.
    hostname = parsed.hostname
    if ".." in hostname or _is_path_traversal(hostname):
        return False
    try:
        from urllib.parse import unquote

        decoded_hostname = unquote(hostname)
        if decoded_hostname != hostname and (
            ".." in decoded_hostname or _is_path_traversal(decoded_hostname)
        ):
            return False
    except Exception:  # noqa: BLE001
        pass
    return True


def validate_json_payload(data: bytes) -> dict[str, Any] | None:
    if not data or not isinstance(data, bytes):
        return None
    if len(data) > _MAX_JSON_SIZE:
        return None
    if b"\x00" in data:
        return None
    try:
        result = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(result, dict):
        return None
    return cast(dict[str, Any], result)


def sanitize_path_segment(segment: str) -> str:
    segment = segment.replace("\x00", "")
    segment = "".join(ch for ch in segment if ord(ch) >= 0x20 or ch in ("\t", "\n", "\r"))
    segment = segment.replace("\\", "/")
    parts = [p for p in segment.split("/") if p and p != "." and p != ".."]
    return "/".join(parts)


def is_within_directory(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        stripped = hostname.strip("[]")
        try:
            ipaddress.ip_address(stripped)
            return True
        except ValueError:
            return False


def _resolve_hostname(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except (OSError, socket.gaierror):
        return None


def _resolve_hostname_stable(hostname: str, samples: int = 3) -> str | None:
    """Resolve ``hostname`` multiple times and require the answer to be stable.

    A bare ``socket.gethostbyname`` check is racy: an attacker controlling
    the authoritative DNS for the replay target can return a public IP for
    the validation lookup and a private/metadata IP for the subsequent
    fetch (TOCTOU). Resolving several times in a row and rejecting the
    hostname when the answer flips makes this attack far harder, though
    it does not eliminate the TOCTOU window. Callers that need a
    *hard* guarantee must additionally pin the resolved IP at request time
    (see ``src.dashboard.fastapi.ssrf_fetch`` for the helper used by the
    fetch layer).
    """
    addresses: list[str] = []
    for _ in range(max(1, samples)):
        addr = _resolve_hostname(hostname)
        if addr is None:
            return None
        if addresses and addr != addresses[0]:
            # Answer flipped between samples - reject as a rebinding attempt.
            return None
        addresses.append(addr)
    return addresses[0] if addresses else None


def _get_replay_allowlist() -> set[str]:
    raw = os.environ.get("DASHBOARD_REPLAY_ALLOWLIST", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _log_ssrf_block(url: str, reason: str) -> None:
    logger.warning("SSRF blocked: %s - reason: %s", url, reason)


def is_safe_replay_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname in _get_replay_allowlist():
            return True
        if _is_ip_literal(hostname):
            ip = ipaddress.ip_address(hostname)
            if str(ip) == _CLOUD_METADATA_IP:
                _log_ssrf_block(url, "Cloud metadata IP literal")
                return False
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                _log_ssrf_block(url, "IP literal is private/loopback/reserved/link-local")
                return False
        lower_host = hostname.lower()
        if lower_host.endswith(_BLOCKED_SUFFIXES):
            _log_ssrf_block(url, "Special-use domain suffix")
            return False
        # Resolve the hostname multiple times to detect DNS rebinding. A
        # naive single resolve leaves a TOCTOU window: an attacker can
        # return a public IP for the safety check and a private/metadata
        # IP for the subsequent fetch. Rejecting the URL when the answer
        # flips between samples closes most of that window.
        ip_str = _resolve_hostname_stable(hostname)
        if ip_str is None:
            _log_ssrf_block(url, "DNS rebinding detected: resolution unstable or failed")
            return False
        if ip_str == _CLOUD_METADATA_IP:
            _log_ssrf_block(url, "Resolves to cloud metadata IP")
            return False
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            _log_ssrf_block(url, "Resolved IP is private/loopback/reserved/link-local")
            return False
        return True
    except (ValueError, OSError, socket.gaierror):
        return False


def security_headers() -> dict[str, str]:
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "font-src 'self'; "
            "img-src 'self' https://www.transparenttextures.com; "
            "connect-src 'self' wss: ws:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "
            "upgrade-insecure-requests"
        ),
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        "X-XSS-Protection": "1; mode=block",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }
