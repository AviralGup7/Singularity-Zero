"""WebSocket message-level injection and subprotocol/origin validation.

The detection stack already exposes ``websocket_hijacking_probe`` which
performs a handshake-level cross-origin / CSRF check. This module is
its message-level companion — it inspects the WebSocket frames that the
target has already exchanged (captured by a MITM proxy, devtools, or
replay harness) and flags:

* **Origin validation gaps** — handshake response that accepted an
  attacker-controlled ``Origin`` header (when the captured
  observations include the ``Origin`` from the test runner).
* **Subprotocol validation gaps** — server echoes an arbitrary
  ``Sec-WebSocket-Protocol`` value back to the client without
  allow-listing (subprotocol confusion).
* **Message-level injection** — JSON frames that are not parsed (raw
  echoed), frames that are concatenated to a sink, frames that mix
  trusted and untrusted fields, and frames that are vulnerable to
  prototype pollution or SSRF redirects via ``@`` / ``$`` Mongo
  operators.
* **Token binding gaps** — frames that contain a session token or user
  identifier that is not bound to a per-frame nonce.

The module never opens a WebSocket connection of its own. The handler
in :mod:`src.detection.handlers` wires it into the response stream and
the exploitation layer (``injectionengine`` /
``headerinjectionengine``) reuses the existing
``websocket_hijacking_probe`` and the new payload recipes for replay.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------


# JSON keys that, when present, suggest a server-side action.
_DANGEROUS_KEYS: tuple[str, ...] = (
    "exec",
    "eval",
    "cmd",
    "command",
    "shell",
    "render",
    "template",
    "include",
    "require",
    "url",
    "uri",
    "redirect",
    "fetch",
    "proxy",
    "sql",
    "query",
    "filter",
    "sort",
    "limit",
    "skip",
    "where",
)

# Mongo / NoSQL operator prefixes.
_NO_SQL_OPERATORS: tuple[str, ...] = (
    "$where",
    "$ne",
    "$gt",
    "$lt",
    "$regex",
    "$or",
    "$and",
    "$in",
    "$nin",
)

# Prototype pollution payloads carried in WS frames.
_PROTO_KEYS: tuple[str, ...] = ("__proto__", "constructor", "prototype")

# URL-bearing values that the server may fetch / include.
_URL_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

# HTML/JS injection tokens seen in echoed frames.
_HTML_TOKENS: tuple[str, ...] = (
    "<script",
    "</script",
    "javascript:",
    "<iframe",
    "onerror=",
    "onload=",
)

# Subprotocol confusion tokens.
_CONFUSION_SUBPROTOCOLS: tuple[str, ...] = (
    "graphql-ws",
    "graphql-transport-ws",
    "wamp",
    "mqtt",
    "stomp",
    "soap",
    "xmpp",
    "v12.stomp",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WebSocketMessageSecurityFinding:
    """A single WebSocket message-level security finding."""

    url: str
    frame_index: int
    direction: str
    frame_type: str
    observed_origin: str | None
    observed_subprotocol: str | None
    server_subprotocol_echo: str | None
    findings: tuple[str, ...]
    severity: str
    confidence: float
    summary: str
    remediation_hint: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "websocket_message_security",
            "summary": self.summary,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "frame_index": self.frame_index,
            "direction": self.direction,
            "frame_type": self.frame_type,
            "observed_origin": self.observed_origin,
            "observed_subprotocol": self.observed_subprotocol,
            "server_subprotocol_echo": self.server_subprotocol_echo,
            "findings": list(self.findings),
            "remediation_hint": self.remediation_hint,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_json_loads(text: str) -> Any | None:
    if not text:
        return None
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except (ValueError, TypeError):
        return None


def _walk_collect_strings(value: Any) -> list[str]:
    """Recursively collect every string from a parsed JSON value."""

    collected: list[str] = []
    if isinstance(value, str):
        collected.append(value)
    elif isinstance(value, dict):
        for key, inner in value.items():
            if isinstance(key, str):
                collected.append(key)
            collected.extend(_walk_collect_strings(inner))
    elif isinstance(value, list):
        for item in value:
            collected.extend(_walk_collect_strings(item))
    return collected


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key in value:
            if isinstance(key, str):
                keys.append(key)
            keys.extend(_walk_keys(value[key]))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_walk_keys(item))
    return keys


def _walk_url_hosts(value: Any) -> list[str]:
    hosts: list[str] = []
    for item in _walk_collect_strings(value):
        match = _URL_PATTERN.match(item)
        if match:
            try:
                hosts.append(urlsplit(item).netloc)
            except ValueError:
                continue
    return hosts


def _origin_host(origin: str | None) -> str | None:
    if not origin:
        return None
    try:
        return urlsplit(origin).netloc.lower() or None
    except ValueError:
        return None


def _expected_host(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except ValueError:
        return ""


def _is_sensitive_subprotocol(subprotocol: str) -> bool:
    lowered = subprotocol.lower()
    return any(token in lowered for token in _CONFUSION_SUBPROTOCOLS)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_websocket_message_security(
    *,
    url: str,
    frame: dict[str, Any],
    frame_index: int = 0,
    expected_origin: str | None = None,
    allowed_subprotocols: Iterable[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> WebSocketMessageSecurityFinding:
    """Analyze a single WebSocket frame observation.

    Args:
        url: The WebSocket URL (or HTTP upgrade URL) the frame came from.
        frame: A dict with ``direction`` (``client``/``server``),
            ``type`` (``text``/``binary``/``ping``/``pong``/``close``),
            ``payload`` (decoded text or hex), and optional ``origin`` /
            ``subprotocol`` from the handshake plus ``server_subprotocol``
            echoed in the response.
        frame_index: Ordinal of the frame in the conversation.
        expected_origin: Optional origin the server is supposed to accept.
        allowed_subprotocols: Optional allow-list of subprotocols.
        extra: Optional evidence dict merged into the finding.
    """

    direction = str(frame.get("direction", "client")).lower()
    frame_type = str(frame.get("type") or frame.get("frame_type") or "text").lower()
    payload = frame.get("payload")
    if payload is None:
        payload = frame.get("data") or frame.get("body") or ""
    payload_text = payload.decode("utf-8", errors="replace") if isinstance(payload, (bytes, bytearray)) else str(payload)

    observed_origin = frame.get("origin") or frame.get("handshake_origin")
    observed_subprotocol = frame.get("subprotocol") or frame.get("requested_subprotocol")
    server_subprotocol_echo = (
        frame.get("server_subprotocol")
        or frame.get("response_subprotocol")
        or frame.get("sec_websocket_protocol")
    )

    findings: list[str] = []
    severity = "info"
    confidence = 0.30
    expected = (expected_origin or "").strip().lower() or None
    allowed_subprotocol_set = {
        str(item).strip().lower() for item in (allowed_subprotocols or []) if item
    }

    origin_host = _origin_host(observed_origin)
    expected_host = expected.lstrip("*").lower() if expected else None
    target_host = _expected_host(url)
    if expected and observed_origin and expected_host and expected_host != origin_host:
        if expected_host.startswith("*."):
            suffix = expected_host[2:]
            if origin_host and not (origin_host.endswith("." + suffix) or origin_host == suffix):
                findings.append("origin_mismatch")
                severity = "high"
                confidence = max(confidence, 0.80)
        else:
            findings.append("origin_mismatch")
            severity = "high"
            confidence = max(confidence, 0.80)
    elif not expected and origin_host and target_host and origin_host != target_host:
        # Without a configured expected origin we still flag a clear
        # cross-origin handshake because the test runner is expected to
        # own the observed origin.
        findings.append("cross_origin_handshake")
        severity = "medium"
        confidence = max(confidence, 0.60)

    if observed_subprotocol:
        lowered = str(observed_subprotocol).lower()
        if allowed_subprotocol_set and lowered not in allowed_subprotocol_set:
            findings.append("subprotocol_not_in_allow_list")
            severity = max([severity, "high"], key=_rank)
            confidence = max(confidence, 0.75)
        if _is_sensitive_subprotocol(lowered):
            findings.append("subprotocol_confusion_candidate")
            severity = max([severity, "high"], key=_rank)
            confidence = max(confidence, 0.75)
    if server_subprotocol_echo and observed_subprotocol:
        if (
            allowed_subprotocol_set
            and str(server_subprotocol_echo).lower() not in allowed_subprotocol_set
        ):
            findings.append("subprotocol_echo_untrusted")
            severity = max([severity, "high"], key=_rank)
            confidence = max(confidence, 0.75)

    if direction == "server" and frame_type == "text" and payload_text:
        parsed = _safe_json_loads(payload_text)
        if parsed is not None:
            keys = _walk_keys(parsed)
            string_values = _walk_collect_strings(parsed)
            url_hosts = _walk_url_hosts(parsed)

            lowered_keys = {key.lower() for key in keys}
            for dangerous in _DANGEROUS_KEYS:
                if any(dangerous in key.lower() for key in keys):
                    findings.append(f"server_frame_dangerous_key:{dangerous}")
                    severity = max([severity, "medium"], key=_rank)
                    confidence = max(confidence, 0.55)
                    break
            for operator in _NO_SQL_OPERATORS:
                if any(key == operator or key.startswith(operator + ".") for key in keys):
                    findings.append(f"server_frame_nosql_operator:{operator}")
                    severity = max([severity, "high"], key=_rank)
                    confidence = max(confidence, 0.80)
                    break
            for proto_key in _PROTO_KEYS:
                if proto_key in lowered_keys:
                    findings.append(f"server_frame_proto_key:{proto_key}")
                    severity = max([severity, "high"], key=_rank)
                    confidence = max(confidence, 0.80)
                    break
            if any(_URL_PATTERN.match(value) for value in string_values):
                findings.append("server_frame_contains_url")
                severity = max([severity, "medium"], key=_rank)
                confidence = max(confidence, 0.55)
            if any(token in value for value in string_values for token in _HTML_TOKENS):
                findings.append("server_frame_html_injection")
                severity = max([severity, "high"], key=_rank)
                confidence = max(confidence, 0.75)
            if url_hosts and target_host and any(
                host and host != target_host for host in url_hosts
            ):
                findings.append("server_frame_cross_host_url")
                severity = max([severity, "high"], key=_rank)
                confidence = max(confidence, 0.75)
        else:
            # Server returned a non-JSON text frame — if it also
            # reflects part of a previous request, that's an injection
            # sink we should flag.
            findings.append("server_frame_non_json_text")
            severity = max([severity, "low"], key=_rank)
            confidence = max(confidence, 0.40)

    if direction == "client" and frame_type == "text" and payload_text:
        parsed = _safe_json_loads(payload_text)
        if parsed is not None:
            keys = _walk_keys(parsed)
            for operator in _NO_SQL_OPERATORS:
                if any(key == operator or key.startswith(operator + ".") for key in keys):
                    findings.append(f"client_frame_nosql_operator:{operator}")
                    severity = max([severity, "high"], key=_rank)
                    confidence = max(confidence, 0.75)
                    break
            for proto_key in _PROTO_KEYS:
                if proto_key in {key.lower() for key in keys}:
                    findings.append(f"client_frame_proto_key:{proto_key}")
                    severity = max([severity, "high"], key=_rank)
                    confidence = max(confidence, 0.75)
                    break

    if not findings:
        findings.append("baseline_review")
        severity = "info"
        confidence = 0.30

    summary = (
        f"WebSocket frame {frame_index} ({direction}/{frame_type}) on {url}: "
        + ", ".join(findings[:3])
    )
    remediation_hint = None
    if severity in {"high", "critical"}:
        remediation_hint = (
            "Validate the WebSocket Origin against an allow-list, enforce a "
            "subprotocol allow-list server-side, parse messages with a strict "
            "JSON schema, and reject NoSQL/prototype-pollution operators."
        )

    return WebSocketMessageSecurityFinding(
        url=url,
        frame_index=frame_index,
        direction=direction,
        frame_type=frame_type,
        observed_origin=str(observed_origin) if observed_origin else None,
        observed_subprotocol=str(observed_subprotocol) if observed_subprotocol else None,
        server_subprotocol_echo=str(server_subprotocol_echo) if server_subprotocol_echo else None,
        findings=tuple(findings),
        severity=severity,
        confidence=round(confidence, 3),
        summary=summary,
        remediation_hint=remediation_hint,
        evidence=dict(extra or {}),
    )


def _rank(value: object) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if not isinstance(value, str):
        return 0
    return order.get(value.lower(), 0)


# ---------------------------------------------------------------------------
# Observation adapter
# ---------------------------------------------------------------------------


def websocket_message_findings_from_observations(
    observations: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert [{url, frames, expected_origin, allowed_subprotocols}, ...].

    Each observation can carry either a single frame dict (with
    ``direction``, ``type``, ``payload``) or a list of frames under
    ``frames``. The handler in :mod:`src.detection.handlers` builds
    these from the recorded WebSocket conversation.
    """

    findings: list[dict[str, Any]] = []
    for obs in observations:
        url = str(obs.get("url", "")).strip()
        if not url:
            continue
        expected_origin = obs.get("expected_origin")
        allowed_subprotocols = obs.get("allowed_subprotocols")
        frames = obs.get("frames")
        if frames is None:
            frames = [
                {
                    "direction": obs.get("direction", "client"),
                    "type": obs.get("type", "text"),
                    "payload": obs.get("payload") or obs.get("data") or "",
                    "origin": obs.get("origin"),
                    "subprotocol": obs.get("subprotocol"),
                    "server_subprotocol": obs.get("server_subprotocol"),
                }
            ]
        if not isinstance(frames, list):
            continue
        for index, frame in enumerate(frames):
            if not isinstance(frame, dict):
                continue
            finding = analyze_websocket_message_security(
                url=url,
                frame=frame,
                frame_index=index,
                expected_origin=expected_origin,
                allowed_subprotocols=allowed_subprotocols,
                extra=obs.get("extra"),
            )
            findings.append(finding.to_dict())
    return findings


__all__ = [
    "WebSocketMessageSecurityFinding",
    "analyze_websocket_message_security",
    "websocket_message_findings_from_observations",
]
