from __future__ import annotations

import logging

"""IP address validation helpers.

A previous version of the project used a regex like
``r"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"`` to detect IPv4 hosts,
which incorrectly accepted values like ``999.999.999.999``.  The stdlib
:mod:`ipaddress` module handles all the edge cases (leading zeros, octal
notation, IPv6, IPv4-mapped IPv6, …) and is what we use here.
"""


import ipaddress
from typing import Final

# Characters that must never appear in a host string.  We reject
# suspicious inputs before passing them to ``ipaddress`` so that
# exception messages stay short and we never log arbitrary user data.
_HOST_FORBIDDEN_CHARS: Final[frozenset[str]] = frozenset(
    {"\x00", "\n", "\r", " ", "\t", "/", "\\", "?", "#", "@"}
)


def is_ipv4(host: str | None) -> bool:
    """Return True if ``host`` is a syntactically valid IPv4 address.

    The input must contain no whitespace, control characters, or URL
    contamination.  The check is intentionally strict so the function
    is safe to use in security-sensitive paths — callers can pre-strip
    inputs themselves if they want lenient behavior.
    """
    if not host or host != host.strip():
        return False
    candidate = host.rstrip(".")
    if any(ch in candidate for ch in _HOST_FORBIDDEN_CHARS):
        return False
    try:
        ipaddress.IPv4Address(candidate)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def is_ip(host: str | None) -> bool:
    """Return True if ``host`` is any valid IP address (IPv4 or IPv6)."""
    if not host or host != host.strip():
        return False
    candidate = host.rstrip(".")
    if any(ch in candidate for ch in _HOST_FORBIDDEN_CHARS):
        return False
    try:
        ipaddress.ip_address(candidate)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def indicator_type_for(host: str | None) -> str:
    """Return ``"IPv4"``, ``"IPv6"``, or ``"domain"`` for threat-intel routing.

    Used as the ``indicator_type`` argument to OTX / VirusTotal clients.
    """
    if not host:
        return "domain"
    candidate = host.strip().rstrip(".")
    if not candidate:
        return "domain"
    try:
        ipaddress.IPv4Address(candidate)
        return "IPv4"
    except (ipaddress.AddressValueError, ValueError) as exc:
        logging.warning("Operation failed in ip_validation.py: %s", exc, exc_info=True)  # noqa: BLE001
    try:
        ipaddress.IPv6Address(candidate)
        return "IPv6"
    except (ipaddress.AddressValueError, ValueError):
        return "domain"


__all__ = ["is_ipv4", "is_ip", "indicator_type_for"]
