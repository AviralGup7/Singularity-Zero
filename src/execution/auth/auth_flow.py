"""Authenticated scanning support.

Two related primitives:

* :class:`AuthFlowRunner` — runs a YAML/JSON auth spec that describes
  how to obtain a session (cookie jar, bearer token, CSRF flow, etc.)
  before the scan starts. The runner validates the session by probing
  a configured ``/me`` endpoint and refreshes the session when
  expiry is detected.

* :class:`OAuthAuthenticator` — performs an OAuth 2.0 authorization
  code flow (with optional PKCE) and stores the resulting access /
  refresh token. The access token is injected into the cookie jar
  and into the request headers used by the active probes.

The two classes are intentionally framework-free: they take an
asynchronous HTTP client factory and a logger and produce a
``SessionContext`` that other parts of the pipeline can consume.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SessionContext:
    """Materialised authentication state ready to inject into probes."""

    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    refresh_token: str | None = None
    obtained_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    user_id: str | None = None

    def is_expired(self, *, skew_seconds: float = 30.0) -> bool:
        if self.expires_at is None:
            return False
        return time.time() >= (self.expires_at - skew_seconds)

    def to_header_dict(self) -> dict[str, str]:
        """Return a header dict suitable for httpx request merging."""
        out = dict(self.headers)
        if self.bearer_token and "Authorization" not in out:
            out["Authorization"] = f"Bearer {self.bearer_token}"
        return out


@dataclass(slots=True)
class AuthStep:
    """A single step in a multi-step authentication flow.

    Each step has a ``method`` and a ``url``. The runner uses
    ``extract`` to pull a value from the response (a JSON key, a
    Set-Cookie header, a hidden form field) and merges it into
    the running session context.
    """

    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    follow_redirects: bool = True
    extract: dict[str, str] = field(default_factory=dict)
    """Map of ``session_key -> extraction_spec``.

    Extraction specs:
        ``"json:path"`` — JSON path like ``"data.token"``
        ``"cookie:name"`` — Set-Cookie name
        ``"header:name"`` — Response header name (case-insensitive)
        ``"form:name"`` — regex over the response body
    """


@dataclass(slots=True)
class AuthSpec:
    """Top-level authentication flow description."""

    name: str
    steps: list[AuthStep] = field(default_factory=list)
    validation_url: str | None = None
    """If set, a successful response from this URL indicates the
    session is valid. Used for refresh detection.
    """
    validation_status: int = 200
    expires_in_field: str | None = None
    """If set, extract ``expires_in`` (seconds) from a step's JSON
    response and use it to compute ``expires_at``.
    """


class AuthFlowRunner:
    """Run an :class:`AuthSpec` and return a :class:`SessionContext`.

    The runner is HTTP-client agnostic. The caller injects an
    ``invoke`` coroutine that takes a step and returns a
    ``(status, headers, body, set_cookies)`` tuple. The same shape
    is produced by every HTTP client, so the runner can be tested
    with a stub ``invoke`` function.
    """

    def __init__(
        self, invoke: Callable[[AuthStep], Awaitable[tuple[int, dict[str, str], str, list[str]]]]
    ):
        self._invoke = invoke

    async def run(self, spec: AuthSpec) -> SessionContext:
        ctx = SessionContext()
        for i, step in enumerate(spec.steps):
            status, headers, body, set_cookies = await self._invoke(step)
            for raw in set_cookies:
                cookie_name, cookie_value = _parse_set_cookie(raw)
                if cookie_name:
                    ctx.cookies[cookie_name] = cookie_value
            for key, spec_str in step.extract.items():
                value = _extract_value(spec_str, body, headers)
                if value is None:
                    continue
                if key == "bearer_token":
                    ctx.bearer_token = value
                elif key == "refresh_token":
                    ctx.refresh_token = value
                else:
                    # Default: treat as a cookie value.
                    ctx.cookies[key] = value
            # Auto-detect expires_in.
            if spec.expires_in_field and not ctx.expires_at:
                try:
                    payload = json.loads(body)
                    expires_in = int(_extract_from_json(payload, spec.expires_in_field) or 0)
                    if expires_in > 0:
                        ctx.expires_at = ctx.obtained_at + expires_in
                except (ValueError, TypeError, json.JSONDecodeError) as exc:
                    logger.warning("Operation failed in auth_flow.py: %s", exc, exc_info=True)  # noqa: BLE001
        if spec.validation_url:
            await self._validate(spec, ctx)
        return ctx

    async def _validate(self, spec: AuthSpec, ctx: SessionContext) -> None:
        """Probe the validation URL to ensure the session is alive."""
        headers = ctx.to_header_dict()
        cookie_header = "; ".join(f"{k}={v}" for k, v in ctx.cookies.items())
        if cookie_header:
            headers.setdefault("Cookie", cookie_header)
        step = AuthStep(method="GET", url=spec.validation_url, headers=headers)
        status, _, _, _ = await self._invoke(step)
        if status != spec.validation_status:
            logger.warning(
                "AuthFlowRunner: validation of session failed (status %d, expected %d)",
                status,
                spec.validation_status,
            )

    async def refresh_if_needed(
        self,
        ctx: SessionContext,
        refresh: AuthStep,
    ) -> SessionContext:
        """Refresh a session using a single-step refresh flow."""
        if not ctx.is_expired():
            return ctx
        status, headers, body, set_cookies = await self._invoke(refresh)
        for raw in set_cookies:
            name, value = _parse_set_cookie(raw)
            if name:
                ctx.cookies[name] = value
        try:
            payload = json.loads(body)
            if "access_token" in payload:
                ctx.bearer_token = str(payload["access_token"])
            if "refresh_token" in payload:
                ctx.refresh_token = str(payload["refresh_token"])
            if "expires_in" in payload:
                ctx.expires_at = time.time() + int(payload["expires_in"])
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            logger.warning("Operation failed in auth_flow.py: %s", exc, exc_info=True)  # noqa: BLE001
        ctx.obtained_at = time.time()
        return ctx


class OAuthAuthenticator:
    """OAuth 2.0 (authorization code, with optional PKCE) flow.

    Performs the full client-side flow:
    1. Build the authorization URL with a PKCE code verifier + challenge.
    2. Wait for the operator to provide the redirect URL (the
       ``callback_received`` coroutine) — the function returns the
       code from the URL's ``code`` query parameter.
    3. Exchange the code at the token URL for an access token.
    4. Persist the resulting :class:`SessionContext`.

    For headless / automated operation the runner expects a
    ``callback_received`` callable that opens a local HTTP server
    and returns the URL the user's browser was redirected to. The
    callback is provided by the operator and the OAuthAuthenticator
    is HTTP-framework-agnostic.
    """

    def __init__(
        self,
        client_id: str,
        authorization_url: str,
        token_url: str,
        redirect_uri: str = "http://127.0.0.1:8400/oauth/callback",
        scope: str = "",
        client_secret: str | None = None,
        use_pkce: bool = True,
        invoke: Callable[
            [str, str, dict[str, str], dict[str, str]], Awaitable[tuple[int, dict[str, str], str]]
        ]
        | None = None,
    ) -> None:
        self.client_id = client_id
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.client_secret = client_secret
        self.use_pkce = use_pkce
        # ``invoke`` is (method, url, headers, form) -> (status, headers, body).
        self._invoke = invoke

    def build_authorize_url(self) -> tuple[str, str]:
        """Build the URL the user should be redirected to.

        Returns ``(url, code_verifier)`` — keep the verifier so the
        token exchange step can use it.
        """
        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
        }
        if self.use_pkce:
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
        url = f"{self.authorization_url}?{urlencode(params)}"
        return url, verifier

    async def exchange_code(
        self,
        code: str,
        code_verifier: str | None = None,
    ) -> SessionContext:
        """Exchange the authorization code for an access token."""
        if self._invoke is None:
            raise RuntimeError("OAuthAuthenticator.exchange_code requires an invoke()")
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        if self.client_secret:
            form["client_secret"] = self.client_secret
        if self.use_pkce and code_verifier:
            form["code_verifier"] = code_verifier
        status, headers, body = await self._invoke("POST", self.token_url, {}, form)
        if status >= 400:
            raise RuntimeError(f"OAuth token exchange failed: status={status} body={body[:200]}")
        payload = json.loads(body)
        ctx = SessionContext(
            bearer_token=str(payload.get("access_token", "")),
            refresh_token=payload.get("refresh_token"),
            obtained_at=time.time(),
            expires_at=time.time() + int(payload.get("expires_in", 3600)),
        )
        return ctx

    async def refresh(
        self,
        ctx: SessionContext,
    ) -> SessionContext:
        """Refresh the access token using the stored refresh token."""
        if not ctx.refresh_token:
            raise RuntimeError("no refresh_token in session context")
        form = {
            "grant_type": "refresh_token",
            "refresh_token": ctx.refresh_token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            form["client_secret"] = self.client_secret
        status, _, body = await self._invoke("POST", self.token_url, {}, form)
        if status >= 400:
            raise RuntimeError(f"OAuth refresh failed: status={status} body={body[:200]}")
        payload = json.loads(body)
        ctx.bearer_token = str(payload.get("access_token", ctx.bearer_token))
        if "refresh_token" in payload:
            ctx.refresh_token = payload["refresh_token"]
        ctx.expires_at = time.time() + int(payload.get("expires_in", 3600))
        ctx.obtained_at = time.time()
        return ctx


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _parse_set_cookie(raw: str) -> tuple[str | None, str]:
    """Extract the name=value pair from a Set-Cookie header value."""
    raw = raw.strip()
    if not raw:
        return None, ""
    first = raw.split(";", 1)[0]
    if "=" not in first:
        return None, ""
    name, value = first.split("=", 1)
    return name.strip(), value.strip()


def _extract_value(spec_str: str, body: str, headers: dict[str, str]) -> str | None:
    """Apply an extraction spec to the response body / headers."""
    if spec_str.startswith("json:"):
        path = spec_str[len("json:") :]
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None
        return _extract_from_json(payload, path)
    if spec_str.startswith("cookie:"):
        return None  # handled by Set-Cookie parser
    if spec_str.startswith("header:"):
        name = spec_str[len("header:") :].strip().lower()
        return headers.get(name)
    if spec_str.startswith("form:"):
        import re

        pattern = spec_str[len("form:") :]
        m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        return m.group(1) if m and m.groups() else (m.group(0) if m else None)
    return None


def _extract_from_json(payload: Any, path: str) -> Any:
    """Tiny JSON-path extractor. Supports ``a.b.c`` and ``a[0]``."""
    if not path:
        return payload
    cur: Any = payload
    import re

    parts = re.split(r"\.(?![^\[]*\])", path)
    for part in parts:
        if cur is None:
            return None
        if "[" in part:
            name, rest = part.split("[", 1)
            if name:
                cur = cur.get(name) if isinstance(cur, dict) else None
            index = int(rest.rstrip("]"))
            cur = cur[index] if isinstance(cur, list) and 0 <= index < len(cur) else None
        else:
            cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


__all__ = [
    "AuthFlowRunner",
    "AuthSpec",
    "AuthStep",
    "OAuthAuthenticator",
    "SessionContext",
]
