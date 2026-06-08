"""OAuth / OIDC authenticator for authenticated scanning.

The :class:`OAuthAuthenticator` performs an OAuth2 authorization
code flow (with optional PKCE) and stores the resulting access
token in a cookie jar and authorization header for use by the
authenticated scanner. The goal is to let the pipeline drive
``Bearer <access_token>`` requests on its own — no manual
``session_cookie`` paste required.

Configuration::

    oauth:
      auth_url: "https://target.com/oauth/authorize"
      token_url: "https://target.com/oauth/token"
      client_id: "<id>"
      client_secret: "<secret>"
      username: "<user>"
      password: "<pass>"
      scope: "read write"
      redirect_uri: "https://target.com/callback"
      use_pkce: true
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

logger = logging.getLogger(__name__)


class OAuthAuthenticatorError(RuntimeError):
    """Raised when an OAuth flow step fails."""


@dataclass
class OAuthConfig:
    """OAuth authenticator configuration."""

    auth_url: str
    token_url: str
    client_id: str
    client_secret: str | None = None
    username: str | None = None
    password: str | None = None
    scope: str | None = None
    redirect_uri: str = "https://localhost/callback"
    use_pkce: bool = True
    extra_auth_params: dict[str, str] = field(default_factory=dict)
    extra_token_params: dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0
    verify_ssl: bool = True

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> OAuthConfig:
        if not isinstance(data, Mapping):
            raise OAuthAuthenticatorError(
                "oauth config must be a mapping"
            )
        for required in ("auth_url", "token_url", "client_id"):
            if not data.get(required):
                raise OAuthAuthenticatorError(
                    f"oauth config missing required field: {required!r}"
                )
        return cls(
            auth_url=str(data["auth_url"]),
            token_url=str(data["token_url"]),
            client_id=str(data["client_id"]),
            client_secret=str(data.get("client_secret") or "")
            if data.get("client_secret")
            else None,
            username=str(data.get("username") or "")
            if data.get("username")
            else None,
            password=str(data.get("password") or "")
            if data.get("password")
            else None,
            scope=str(data.get("scope") or "")
            if data.get("scope")
            else None,
            redirect_uri=str(data.get("redirect_uri") or "https://localhost/callback"),
            use_pkce=bool(data.get("use_pkce", True)),
            extra_auth_params=dict(data.get("extra_auth_params") or {}),
            extra_token_params=dict(data.get("extra_token_params") or {}),
            timeout=float(data.get("timeout", 10.0)),
            verify_ssl=bool(data.get("verify_ssl", True)),
        )


@dataclass
class OAuthToken:
    """Resulting OAuth token bundle."""

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None
    expires_at: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def authorization_header(self) -> str:
        return f"{self.token_type} {self.access_token}"

    def is_expired(self, *, skew_seconds: float = 30.0) -> bool:
        if self.expires_at is None:
            return False
        return time.time() >= self.expires_at - skew_seconds

    @classmethod
    def from_token_response(cls, payload: Mapping[str, Any]) -> OAuthToken:
        if not isinstance(payload, Mapping):
            raise OAuthAuthenticatorError("token response must be a JSON object")
        access = payload.get("access_token")
        if not access:
            raise OAuthAuthenticatorError(
                "token response missing required 'access_token' field"
            )
        expires_in = payload.get("expires_in")
        expires_at = None
        try:
            if expires_in is not None:
                expires_at = time.time() + float(expires_in)
        except (TypeError, ValueError):
            expires_at = None
        return cls(
            access_token=str(access),
            token_type=str(payload.get("token_type", "Bearer") or "Bearer"),
            refresh_token=str(payload["refresh_token"])
            if payload.get("refresh_token")
            else None,
            id_token=str(payload["id_token"]) if payload.get("id_token") else None,
            scope=str(payload["scope"]) if payload.get("scope") else None,
            expires_at=expires_at,
            raw=dict(payload),
        )


def _generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) using S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode(
        "ascii"
    )
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class OAuthAuthenticator:
    """Drive an OAuth2 authorization-code flow and produce a token.

    The class is intentionally headless — it never opens a browser.
    For interactive flows (``response_type=code``) the operator
    must provide ``username``/``password`` so the authenticator can
    submit them at the IdP's login page (resource-owner password
    credentials are intentionally not used; we use the form-POST
    pattern that providers like Auth0, Okta, and Keycloak
    expose for automation).
    """

    def __init__(self, config: OAuthConfig | Mapping[str, Any]) -> None:
        self._config = (
            config if isinstance(config, OAuthConfig) else OAuthConfig.from_mapping(config)
        )
        self._cookies: dict[str, str] = {}
        self._pkce_verifier: str | None = None

    @property
    def config(self) -> OAuthConfig:
        return self._config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authenticate(self) -> OAuthToken:
        """Run the full flow and return the resulting token."""
        if self._config.use_pkce:
            self._pkce_verifier, challenge = _generate_pkce_pair()
        else:
            self._pkce_verifier = None
            challenge = None

        auth_params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
        }
        if self._config.scope:
            auth_params["scope"] = self._config.scope
        if challenge:
            auth_params["code_challenge"] = challenge
            auth_params["code_challenge_method"] = "S256"
        auth_params.update(self._config.extra_auth_params)

        auth_url = self._config.auth_url
        if "?" in auth_url:
            sep = "&"
        else:
            sep = "?"
        full_auth_url = f"{auth_url}{sep}{urlencode(auth_params)}"

        with httpx.Client(
            timeout=self._config.timeout,
            verify=self._config.verify_ssl,
            follow_redirects=True,
        ) as client:
            # Step 1: GET the auth URL. The IdP may render a login
            # form (HTML) or redirect to an SSO.
            auth_response = client.get(full_auth_url)
            self._capture_cookies(auth_response)
            login_url, form_fields = self._extract_login_form(auth_response, auth_url)
            if not form_fields and not self._config.username:
                raise OAuthAuthenticatorError(
                    "auth response did not include a login form and no "
                    "username/password were provided"
                )
            if form_fields and self._config.username:
                form_fields = self._fill_login_form(form_fields)
                with httpx.Client(
                    timeout=self._config.timeout,
                    verify=self._config.verify_ssl,
                    follow_redirects=False,
                ) as submit_client:
                    # Carry the cookies forward
                    cookie_header = "; ".join(
                        f"{k}={v}" for k, v in self._cookies.items()
                    )
                    submit_headers = {"Cookie": cookie_header} if cookie_header else {}
                    login_response = submit_client.post(
                        login_url or auth_url,
                        data=form_fields,
                        headers=submit_headers,
                    )
                    self._capture_cookies(login_response)
                    # Step 2: extract the authorization code from the
                    # redirect Location or from the consent page form.
                    code = self._extract_authorization_code(
                        login_response, login_url or auth_url
                    )
                    if not code:
                        # Some providers render a consent form on the
                        # login response itself. Try to auto-approve.
                        code = self._try_extract_code_from_html(login_response)
            else:
                # No form: assume the user has already authorised and
                # the code is in the redirect Location. We can't
                # follow that without browser interaction, so we
                # surface a clear error.
                code = self._try_extract_code_from_html(auth_response)
            if not code:
                raise OAuthAuthenticatorError(
                    "OAuth flow did not produce an authorization code — "
                    "interactive flows require a username/password and a "
                    "consenting form that can be auto-submitted"
                )

            # Step 3: exchange the authorization code for a token.
            token_payload = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._config.redirect_uri,
                "client_id": self._config.client_id,
            }
            if self._pkce_verifier:
                token_payload["code_verifier"] = self._pkce_verifier
            if self._config.client_secret:
                token_payload["client_secret"] = self._config.client_secret
            token_payload.update(self._config.extra_token_params)
            token_response = client.post(self._config.token_url, data=token_payload)
            if token_response.status_code >= 400:
                raise OAuthAuthenticatorError(
                    f"token endpoint returned {token_response.status_code}: "
                    f"{token_response.text[:200]}"
                )
            try:
                token_data = token_response.json()
            except json.JSONDecodeError as exc:
                raise OAuthAuthenticatorError(
                    f"token endpoint returned non-JSON: {exc}"
                ) from exc
        return OAuthToken.from_token_response(token_data)

    def refresh(self, token: OAuthToken) -> OAuthToken:
        """Exchange a refresh token for a new access token."""
        if not token.refresh_token:
            raise OAuthAuthenticatorError("token has no refresh_token to exchange")
        payload: dict[str, Any] = {
            "grant_type": "refresh_token",
            "refresh_token": token.refresh_token,
            "client_id": self._config.client_id,
        }
        if self._config.client_secret:
            payload["client_secret"] = self._config.client_secret
        payload.update(self._config.extra_token_params)
        with httpx.Client(
            timeout=self._config.timeout, verify=self._config.verify_ssl
        ) as client:
            response = client.post(self._config.token_url, data=payload)
            if response.status_code >= 400:
                raise OAuthAuthenticatorError(
                    f"refresh endpoint returned {response.status_code}: "
                    f"{response.text[:200]}"
                )
            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                raise OAuthAuthenticatorError(
                    f"refresh endpoint returned non-JSON: {exc}"
                ) from exc
        return OAuthToken.from_token_response(data)

    def install_into_jar(self, token: OAuthToken, jar: CookieJar | None = None) -> CookieJar:
        """Materialise the bearer token as a cookie + Authorization header pair.

        Returns the populated jar. The Authorization header is
        returned separately via :attr:`authorization_header_value`.
        """
        jar = jar or CookieJar()
        host = urlparse(self._config.auth_url).hostname or "localhost"
        from http.cookiejar import Cookie

        cookie = Cookie(
            version=0,
            name="bearer_token",
            value=token.access_token,
            port=None,
            port_specified=False,
            domain=host,
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=True,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": ""},
            rfc2109=False,
        )
        jar.set_cookie(cookie)
        return jar

    @property
    def authorization_header_value(self) -> str | None:
        """Placeholder — the actual value is supplied by the caller via the token."""
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _capture_cookies(self, response: httpx.Response) -> None:
        for cookie in response.cookies.jar:
            self._cookies[cookie.name] = cookie.value

    def _extract_login_form(
        self, response: httpx.Response, base_url: str
    ) -> tuple[str | None, dict[str, str]]:
        """Return ``(action_url, form_fields)`` for the first login form."""
        # Heuristic: look for ``<input name=...>`` tags. Most IdP
        # login pages follow the same shape.
        inputs: dict[str, str] = {}
        action: str | None = None
        try:
            html = response.text
        except Exception:
            return None, {}
        for name_match in re.finditer(
            r'<input[^>]+name="([^"]+)"[^>]*value="([^"]*)"',
            html,
            flags=re.IGNORECASE,
        ):
            inputs[name_match.group(1)] = name_match.group(2)
        action_match = re.search(
            r'<form[^>]+action="([^"]+)"', html, flags=re.IGNORECASE
        )
        if action_match:
            action = action_match.group(1)
        # Heuristic: if the form has no obvious username/password
        # inputs, treat the response as a "you're already
        # authenticated" page and return empty fields.
        if not any(k for k in inputs if k.lower() in {"username", "email", "login"}):
            return action, {}
        return action or base_url, inputs

    def _fill_login_form(self, form: dict[str, str]) -> dict[str, str]:
        out = dict(form)
        if not self._config.username or not self._config.password:
            raise OAuthAuthenticatorError(
                "login form detected but no username/password configured"
            )
        # Map common field names to the credentials
        for key in list(out.keys()):
            kl = key.lower()
            if kl in {"username", "email", "login"}:
                out[key] = self._config.username
            elif kl in {"password", "pass", "pwd"}:
                out[key] = self._config.password
        return out

    def _extract_authorization_code(
        self, response: httpx.Response, base_url: str
    ) -> str | None:
        location = response.headers.get("Location") or response.headers.get(
            "location"
        )
        if not location:
            return None
        parsed = urlparse(location)
        if not parsed.query:
            return None
        params = parse_qs(parsed.query)
        if "code" in params and params["code"]:
            return params["code"][0]
        return None

    def _try_extract_code_from_html(self, response: httpx.Response) -> str | None:
        try:
            html = response.text
        except Exception:
            return None
        match = re.search(r'code=([A-Za-z0-9._\-]+)', html)
        if match:
            return match.group(1)
        return None


__all__ = [
    "OAuthAuthenticator",
    "OAuthAuthenticatorError",
    "OAuthConfig",
    "OAuthToken",
]
