"""Deterministic Canonical Target Identity and Normalization Engine.

Provides an immutable, tamper-resistant representation of a network/web scan target:
- IDNA Punycode and trailing dot normalization
- Scheme lowercasing and default port elision (HTTP:80, HTTPS:443)
- POSIX directory traversal resolution (/a/b/../c -> /a/c) and matrix parameter stripping
- Query parameter canonical alphabetical sorting and fragment elimination
- Pinned DNS snapshot resolution to mitigate TOCTOU DNS rebinding and SSRF attacks
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import re
import socket
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class DnsSnapshot:
    """Immutable snapshot of DNS resolution for a target host."""

    resolved_ips: tuple[str, ...]
    primary_ip: str
    is_private_or_loopback: bool
    resolved_at_unix: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolved_ips": list(self.resolved_ips),
            "primary_ip": self.primary_ip,
            "is_private_or_loopback": self.is_private_or_loopback,
            "resolved_at_unix": self.resolved_at_unix,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsSnapshot:
        return cls(
            resolved_ips=tuple(data.get("resolved_ips", ())),
            primary_ip=str(data.get("primary_ip", "")),
            is_private_or_loopback=bool(data.get("is_private_or_loopback", False)),
            resolved_at_unix=float(data.get("resolved_at_unix", 0.0)),
        )


@dataclass(frozen=True, slots=True)
class CanonicalTargetIdentity:
    """Immutable, fully-canonicalized target identity."""

    raw_url: str
    scheme: str
    hostname: str
    port: int
    path: str
    query: str
    canonical_url: str
    identity_hash: str
    dns_snapshot: DnsSnapshot | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_url": self.raw_url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "canonical_url": self.canonical_url,
            "identity_hash": self.identity_hash,
            "dns_snapshot": self.dns_snapshot.to_dict() if self.dns_snapshot else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CanonicalTargetIdentity:
        dns = (
            DnsSnapshot.from_dict(data["dns_snapshot"])
            if data.get("dns_snapshot")
            else None
        )
        return cls(
            raw_url=str(data.get("raw_url", "")),
            scheme=str(data.get("scheme", "https")),
            hostname=str(data.get("hostname", "")),
            port=int(data.get("port", 443)),
            path=str(data.get("path", "/")),
            query=str(data.get("query", "")),
            canonical_url=str(data.get("canonical_url", "")),
            identity_hash=str(data.get("identity_hash", "")),
            dns_snapshot=dns,
        )


def _is_ip_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def _resolve_dns_pinned(hostname: str, timestamp: float) -> DnsSnapshot:
    try:
        # If hostname is already an IP address
        ip_obj = ipaddress.ip_address(hostname)
        ip_str = str(ip_obj)
        return DnsSnapshot(
            resolved_ips=(ip_str,),
            primary_ip=ip_str,
            is_private_or_loopback=ip_obj.is_private or ip_obj.is_loopback,
            resolved_at_unix=timestamp,
        )
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips: list[str] = []
        for info in addr_info:
            sockaddr = info[4]
            ip_candidate = sockaddr[0]
            if ip_candidate not in ips:
                ips.append(ip_candidate)
        
        if not ips:
            ips = ["0.0.0.0"]

        primary = ips[0]
        is_private = any(_is_ip_private(ip) for ip in ips)
        return DnsSnapshot(
            resolved_ips=tuple(ips),
            primary_ip=primary,
            is_private_or_loopback=is_private,
            resolved_at_unix=timestamp,
        )
    except Exception:
        return DnsSnapshot(
            resolved_ips=(),
            primary_ip="0.0.0.0",
            is_private_or_loopback=False,
            resolved_at_unix=timestamp,
        )


def canonicalize_target(
    raw_input: str,
    default_scheme: str = "https",
    resolve_dns: bool = False,
    now_unix: float = 0.0,
) -> CanonicalTargetIdentity:
    """Deterministically canonicalize a raw URL or hostname string into a CanonicalTargetIdentity."""
    trimmed = raw_input.strip()
    if not trimmed:
        raise ValueError("Cannot canonicalize empty target")

    # Add scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", trimmed):
        trimmed = f"{default_scheme}://{trimmed}"

    parsed = urllib.parse.urlsplit(trimmed)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https", "ws", "wss"):
        raise ValueError(f"Unsupported URI scheme: {scheme}")

    # Extract and normalize hostname
    netloc = parsed.netloc
    if "@" in netloc:
        # Strip userinfo for security
        _, netloc = netloc.rsplit("@", 1)

    hostname = ""
    port = 0
    if ":" in netloc and not (netloc.startswith("[") and netloc.endswith("]")):
        host_part, port_part = netloc.rsplit(":", 1)
        hostname = host_part
        try:
            port = int(port_part)
        except ValueError:
            port = 0
    else:
        hostname = netloc

    # Strip IPv6 enclosing brackets if present
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]

    # Lowercase & IDNA Punycode conversion
    hostname = hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except Exception:
        hostname = hostname.lower()

    # Determine canonical port
    default_port = 443 if scheme in ("https", "wss") else 80
    if port <= 0 or port > 65535:
        port = default_port

    # Normalize Path: POSIX traversal resolution & matrix parameter removal
    path = parsed.path
    if not path:
        path = "/"
    
    # Strip matrix parameters (;param=val)
    path = re.sub(r";[^/]*", "", path)
    
    # URL unquote & resolve traversal
    unquoted_path = urllib.parse.unquote(path)
    unquoted_path = re.sub(r"/+", "/", unquoted_path)
    # POSIX path normalization
    normalized_path = posixpath.normpath(unquoted_path)
    normalized_path = re.sub(r"/+", "/", normalized_path)
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    if unquoted_path.endswith("/") and not normalized_path.endswith("/"):
        normalized_path += "/"

    # Normalize Query: sort parameters canonically
    query_str = parsed.query
    if query_str:
        query_params = urllib.parse.parse_qsl(query_str, keep_blank_values=True)
        # Sort by key, then value
        query_params.sort(key=lambda item: (item[0], item[1]))
        normalized_query = urllib.parse.urlencode(query_params)
    else:
        normalized_query = ""

    # Reconstruct Canonical URL (elide default port)
    if port == default_port:
        canonical_netloc = hostname
    else:
        canonical_netloc = f"{hostname}:{port}"

    canonical_url = urllib.parse.urlunsplit((
        scheme,
        canonical_netloc,
        normalized_path,
        normalized_query,
        "",  # Fragments are strictly eliminated
    ))

    # Compute deterministic SHA-256 identity hash
    identity_hash = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()

    dns_snap = None
    if resolve_dns:
        dns_snap = _resolve_dns_pinned(hostname, now_unix)

    return CanonicalTargetIdentity(
        raw_url=raw_input,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=normalized_path,
        query=normalized_query,
        canonical_url=canonical_url,
        identity_hash=identity_hash,
        dns_snapshot=dns_snap,
    )


def canonical_state_encode(version: str, state: Any) -> bytes:
    """Canonical State Serialization Algorithm (Axiom 7 / Contract Section 7).

    Rules:
    - Schema version header: version:SCHEMA_VERSION
    - Maps/Dicts: strictly sorted lexicographically by keys
    - Sets/Frozensets: deterministically sorted by elements
    - Lists/Tuples: sequence order preserved
    - Strings: Unicode NFC normalized
    - Numbers: exact integers (NaN, +inf, -inf rejected; -0.0 -> +0.0)
    """
    import math
    import unicodedata

    def _normalize(val: Any) -> Any:
        if isinstance(val, (str, bytes)):
            if isinstance(val, bytes):
                return val.decode("utf-8", errors="replace")
            return unicodedata.normalize("NFC", val)
        if isinstance(val, (int, bool)):
            return val
        if isinstance(val, float):
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"Invalid non-finite float in canonical state encoding: {val}")
            if val == 0.0:
                return 0.0
            return val
        if isinstance(val, (dict, Mapping)):
            sorted_items = sorted((_normalize(k), _normalize(v)) for k, v in val.items())
            return dict(sorted_items)
        if isinstance(val, (set, frozenset)):
            normalized_list = [_normalize(item) for item in val]
            try:
                normalized_list.sort()
            except TypeError:
                normalized_list.sort(key=str)
            return normalized_list
        if isinstance(val, (list, tuple)):
            return [_normalize(item) for item in val]
        if hasattr(val, "to_dict") and callable(val.to_dict):
            return _normalize(val.to_dict())
        return str(val)

    normalized_tree = {
        "__schema_version__": version,
        "__state__": _normalize(state),
    }

    encoded_json = json.dumps(
        normalized_tree,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return encoded_json.encode("utf-8")


def compute_canonical_state_hash(version: str, state: Any) -> str:
    """Compute deterministic SHA-256 state hash using canonical state encoding."""
    encoded_bytes = canonical_state_encode(version, state)
    return hashlib.sha256(encoded_bytes).hexdigest()

