from __future__ import annotations

import logging

"""Domain validation and normalization helpers.

A previous version of the project compiled the same domain-validation
regex in three places (``recon/subdomains.py``,
``recon/sources/virustotal.py`` and ``recon/sources/rapiddns.py``) and
had a slightly different normalize function in two of them.  This
module is the single source of truth.

The regex follows RFC 1035 / 1123 with a length cap of 253 characters
(``example.com`` etc.) and rejects anything containing whitespace,
slashes, query markers, or null bytes.
"""


import ipaddress
import re
from typing import Final

DOMAIN_PATTERN: Final[str] = (
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$"
)

_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(DOMAIN_PATTERN, re.IGNORECASE)

# Strings that must never appear in a domain input — these are SSRF
# attempts (null bytes, encoded nulls, line terminators) and URL
# contamination (slashes, query markers, at sign, etc.).
_FORBIDDEN_STRINGS: Final[frozenset[str]] = frozenset(
    {
        "\x00",
        "%00",
        "\n",
        "\r",
        "%0a",
        "%0d",
        "%0A",
        "%0D",
        "/",
        "\\",
        ":",
        "@",
        "?",
        "#",
        " ",
        "\t",
    }
)


def is_safe_domain(domain: str | None) -> bool:
    """Strict validation for a domain input.

    Rejects inputs that contain SSRF markers (null bytes, encoded null
    bytes, line terminators) and URL contamination (slashes, query
    markers, ``:``, ``@``, whitespace).  Returns ``False`` for any input
    that does not match the RFC 1035 / 1123 domain pattern.  Inputs
    that look like IP addresses (valid or malformed) are also rejected
    because this function is intended for *hostname* inputs.
    """
    if not domain:
        return False
    lowered = domain.lower()
    for bad in _FORBIDDEN_STRINGS:
        if bad in lowered:
            return False
    if _looks_like_ip(lowered):
        return False
    return bool(_DOMAIN_RE.fullmatch(domain))


def normalize_domain(domain: str | None) -> str:
    """Normalize a domain string and return it if valid, else ``""``.

    Performs: strip whitespace, lowercase, strip trailing dots, reject
    inputs containing forbidden characters, and validate against the
    domain regex.  Returns the empty string for anything that is empty
    or that looks like an IP address (valid or malformed).  The empty
    string signals "invalid input" so callers can short-circuit cleanly.
    """
    cleaned = str(domain or "").strip().lower().rstrip(".")
    if not cleaned:
        return ""
    for bad in _FORBIDDEN_STRINGS:
        if bad in cleaned:
            return ""
    if _looks_like_ip(cleaned):
        return ""
    if not _DOMAIN_RE.fullmatch(cleaned):
        return ""
    return cleaned


def _looks_like_ip(value: str) -> bool:
    """Return True if ``value`` is a valid IP or a malformed IP-shaped string.

    This guards against cases like ``"999.999.999.999"`` slipping past
    the domain regex when callers pass a numeric input.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except (ipaddress.AddressValueError, ValueError) as exc:
        logging.warning("Operation failed in domain_validation.py: %s", exc, exc_info=True)  # noqa: BLE001
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return False


__all__ = ["is_safe_domain", "normalize_domain", "DOMAIN_PATTERN"]
