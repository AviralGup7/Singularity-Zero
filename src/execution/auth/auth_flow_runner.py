"""Multi-step authentication flow runner.

Bug bounty programs almost always require authenticated testing. The
runner that executes probes (``execution/steps/runner.py``) accepts
``cookie_jars`` and ``session_cookie`` but historically left the
operator to manually paste a session cookie from their browser.

This module adds an :class:`AuthFlowRunner` that drives a fully
declarative auth flow before the scan starts and stores the result
in the executor's session registry. Supported step kinds:

* ``get``              - HTTP GET (used to harvest CSRF tokens).
* ``post_form``        - HTTP POST with form-encoded body (login).
* ``post_json``        - HTTP POST with JSON body.
* ``extract_cookie``   - Pull a named cookie from the response jar
                         into a session variable.
* ``extract_header``   - Pull a response header into a session
                         variable.
* ``extract_regex``    - Apply a regex to the response body and store
                         the first matching group.
* ``extract_jsonpath`` - Apply a simple JSON path to the body.
* ``refresh_token``    - OAuth2 refresh-token grant against a
                         token_url. Stores ``access_token`` /
                         ``refresh_token`` in the session.
* ``validate``         - Probe a known-authenticated endpoint and
                         fail the flow when the response is 401/403.

Flows are declared as YAML/JSON. Example::

    auth_flow:
      - step: get
        url: https://target.com/login
        save_as: login_page
      - step: extract_regex
        from: login_page
        pattern: 'name="csrf_token" value="([^"]+)"'
        save_as: csrf
      - step: post_form
        url: https://target.com/login
        body:
          csrf_token: "${csrf}"
          username: "${user}"
          password: "${pass}"
        save_as: login_response
      - step: extract_cookie
        from: login_response
        name: session
        save_as: session_cookie
      - step: validate
        url: https://target.com/api/me
        expect_status: 200
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Any, ClassVar

import httpx

logger = logging.getLogger(__name__)


class AuthFlowError(RuntimeError):
    """Raised when an auth flow step fails irrecoverably."""


@dataclass
class AuthFlowStep:
    """A single step in an auth flow."""

    step: str
    # Generic step fields, populated based on ``step`` type.
    url: str | None = None
    method: str = "GET"
    body: dict[str, Any] | None = None
    body_type: str = "form"
    headers: dict[str, str] = field(default_factory=dict)
    from_step: str | None = None
    pattern: str | None = None
    jsonpath: str | None = None
    name: str | None = None
    save_as: str | None = None
    expect_status: int = 200
    token_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None
    # Free-form step data preserved for forward-compat with custom
    # runner extensions.
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthFlowResult:
    """Result of running an auth flow."""

    session_cookie: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    variables: dict[str, str] = field(default_factory=dict)
    validated: bool = False
    steps_executed: int = 0
    failure_reason: str | None = None


class AuthFlowRunner:
    """Execute a multi-step auth flow and produce an authenticated session.

    The runner is intentionally tiny: it doesn't depend on the
    larger execution engine and can be invoked synchronously from a
    job bootstrap path or from a CLI.
    """

    SUPPORTED_STEPS: ClassVar[frozenset[str]] = frozenset(
        {
            "get",
            "post_form",
            "post_json",
            "extract_cookie",
            "extract_header",
            "extract_regex",
            "extract_jsonpath",
            "refresh_token",
            "validate",
        }
    )

    def __init__(
        self,
        steps: list[Mapping[str, Any] | AuthFlowStep],
        *,
        variables: Mapping[str, str] | None = None,
        timeout: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        self._steps = [self._coerce_step(s) for s in steps]
        self._variables: dict[str, str] = dict(variables or {})
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._responses: dict[str, httpx.Response] = {}
        self._jar = CookieJar()

    @staticmethod
    def _coerce_step(raw: Mapping[str, Any] | AuthFlowStep) -> AuthFlowStep:
        if isinstance(raw, AuthFlowStep):
            return raw
        if not isinstance(raw, Mapping):
            raise AuthFlowError(f"auth step must be a mapping, got {type(raw).__name__}")
        return AuthFlowStep(
            step=str(raw.get("step", "")),
            url=raw.get("url"),
            method=str(raw.get("method", "GET")),
            body=raw.get("body"),
            body_type=str(raw.get("body_type", "form")),
            headers=dict(raw.get("headers") or {}),
            from_step=raw.get("from") or raw.get("from_step"),
            pattern=raw.get("pattern"),
            jsonpath=raw.get("jsonpath"),
            name=raw.get("name"),
            save_as=raw.get("save_as"),
            expect_status=int(raw.get("expect_status", 200)),
            token_url=raw.get("token_url"),
            client_id=raw.get("client_id"),
            client_secret=raw.get("client_secret"),
            scope=raw.get("scope"),
            extras={k: v for k, v in raw.items() if k not in _STEP_FIELDS},
        )

    def run(self) -> AuthFlowResult:
        """Execute the configured flow.

        Returns an :class:`AuthFlowResult` populated with the final
        session cookie, captured variables, and a ``validated`` flag
        indicating whether the optional ``validate`` step succeeded.
        """
        result = AuthFlowResult()
        cookies: dict[str, str] = {}
        for i, step in enumerate(self._steps):
            if step.step not in self.SUPPORTED_STEPS:
                raise AuthFlowError(
                    f"unsupported auth step: {step.step!r} (supported: "
                    f"{sorted(self.SUPPORTED_STEPS)})"
                )
            try:
                self._execute(step, result, cookies)
            except AuthFlowError:
                raise
            except Exception as exc:
                raise AuthFlowError(
                    f"auth step #{i + 1} ({step.step}) failed: {exc}"
                ) from exc
            result.steps_executed = i + 1
        result.variables.update(self._variables)
        result.cookies.update(cookies)
        if result.session_cookie is None and "session" in cookies:
            result.session_cookie = cookies["session"]
        return result

    # ------------------------------------------------------------------
    # Step implementations
    # ------------------------------------------------------------------

    def _execute(
        self,
        step: AuthFlowStep,
        result: AuthFlowResult,
        cookies: dict[str, str],
    ) -> None:
        if step.step in {"get", "post_form", "post_json"}:
            self._do_request_step(step, result, cookies)
        elif step.step == "extract_cookie":
            self._do_extract_cookie(step, result, cookies)
        elif step.step == "extract_header":
            self._do_extract_header(step, result)
        elif step.step == "extract_regex":
            self._do_extract_regex(step, result)
        elif step.step == "extract_jsonpath":
            self._do_extract_jsonpath(step, result)
        elif step.step == "refresh_token":
            self._do_refresh_token(step, result)
        elif step.step == "validate":
            self._do_validate(step, result, cookies)
        else:  # pragma: no cover — guarded earlier
            raise AuthFlowError(f"unsupported step: {step.step}")

    def _render(self, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return value.format(**self._variables)
        except (KeyError, IndexError):
            if "{{" in value or "}}" in value:
                return value.replace("{{", "{").replace("}}", "}")
            return value

    def _render_headers(self, headers: dict[str, str]) -> dict[str, str]:
        return {k: self._render(v) or "" for k, v in headers.items()}

    def _do_request_step(
        self,
        step: AuthFlowStep,
        result: AuthFlowResult,
        cookies: dict[str, str],
    ) -> None:
        if not step.url:
            raise AuthFlowError(f"{step.step} step requires a url")
        url = self._render(step.url) or step.url
        method = step.method.upper() or (
            "POST" if step.step in {"post_form", "post_json"} else "GET"
        )
        headers = self._render_headers(step.headers)
        body: str | None = None
        if step.body is not None and method != "GET":
            if step.step == "post_json" or step.body_type == "json":
                rendered = self._render_json_body(step.body)
                body = json.dumps(rendered)
                headers.setdefault("Content-Type", "application/json")
            else:
                rendered = self._render_form_body(step.body)
                body = urlencode(rendered)
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        # Apply cookies collected so far
        if cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_header
        with httpx.Client(
            timeout=self._timeout, verify=self._verify_ssl, follow_redirects=True
        ) as client:
            response = client.request(
                method, url, headers=headers, content=body
            )
        # Capture cookies set on this response
        self._capture_cookies(response, cookies)
        if step.save_as:
            self._responses[step.save_as] = response

    def _do_extract_cookie(
        self,
        step: AuthFlowStep,
        result: AuthFlowResult,
        cookies: dict[str, str],
    ) -> None:
        if not step.from_step or not step.name:
            raise AuthFlowError("extract_cookie step requires 'from' and 'name'")
        response = self._responses.get(step.from_step)
        if response is None:
            raise AuthFlowError(
                f"extract_cookie: no response captured for step {step.from_step!r}"
            )
        for header_value in response.headers.get_list("set-cookie"):
            try:
                parts = header_value.split(";", 1)[0].strip()
                if "=" not in parts:
                    continue
                cookie_name, cookie_value = parts.split("=", 1)
                cookie_name = cookie_name.strip()
                if cookie_name == step.name:
                    value = cookie_value.strip()
                    cookies[step.name] = value
                    if step.save_as:
                        self._variables[step.save_as] = value
                        if step.name == "session":
                            result.session_cookie = value
                    return
            except Exception as exc:
                logger.debug("Cookie extraction failed for %s: %s", step.name, exc)
                continue
        if step.name in cookies:
            value = cookies[step.name]
            if step.save_as:
                self._variables[step.save_as] = value
                if step.name == "session":
                    result.session_cookie = value
            return
        raise AuthFlowError(
            f"extract_cookie: cookie {step.name!r} not found in response"
        )

    def _do_extract_header(self, step: AuthFlowStep, result: AuthFlowResult) -> None:
        if not step.from_step or not step.name:
            raise AuthFlowError("extract_header step requires 'from' and 'name'")
        response = self._responses.get(step.from_step)
        if response is None:
            raise AuthFlowError(
                f"extract_header: no response captured for step {step.from_step!r}"
            )
        value = response.headers.get(step.name)
        if value is None:
            raise AuthFlowError(
                f"extract_header: header {step.name!r} not found in response"
            )
        if step.save_as:
            self._variables[step.save_as] = value
            result.headers[step.name] = value

    def _do_extract_regex(self, step: AuthFlowStep, result: AuthFlowResult) -> None:
        if not step.from_step or not step.pattern:
            raise AuthFlowError("extract_regex step requires 'from' and 'pattern'")
        response = self._responses.get(step.from_step)
        if response is None:
            raise AuthFlowError(
                f"extract_regex: no response captured for step {step.from_step!r}"
            )
        match = re.search(step.pattern, response.text)
        if not match:
            raise AuthFlowError(
                f"extract_regex: pattern {step.pattern!r} did not match"
            )
        value = match.group(1) if match.groups() else match.group(0)
        if step.save_as:
            self._variables[step.save_as] = value

    def _do_extract_jsonpath(self, step: AuthFlowStep, result: AuthFlowResult) -> None:
        if not step.from_step or not step.jsonpath:
            raise AuthFlowError(
                "extract_jsonpath step requires 'from' and 'jsonpath'"
            )
        response = self._responses.get(step.from_step)
        if response is None:
            raise AuthFlowError(
                f"extract_jsonpath: no response captured for step {step.from_step!r}"
            )
        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise AuthFlowError(
                f"extract_jsonpath: response is not valid JSON: {exc}"
            ) from exc
        value = _resolve_jsonpath(data, step.jsonpath)
        if value is None:
            raise AuthFlowError(
                f"extract_jsonpath: path {step.jsonpath!r} did not resolve"
            )
        if step.save_as:
            self._variables[step.save_as] = str(value)

    def _do_refresh_token(
        self, step: AuthFlowStep, result: AuthFlowResult
    ) -> None:
        if not step.token_url or not step.client_id or not step.client_secret:
            raise AuthFlowError(
                "refresh_token step requires token_url, client_id, client_secret"
            )
        refresh_token = self._variables.get("refresh_token") or step.extras.get(
            "refresh_token"
        )
        if not refresh_token:
            raise AuthFlowError(
                "refresh_token: no refresh_token variable or step.refresh_token set"
            )
        payload = {
            "grant_type": "refresh_token",
            "client_id": step.client_id,
            "client_secret": step.client_secret,
            "refresh_token": refresh_token,
        }
        if step.scope:
            payload["scope"] = step.scope
        with httpx.Client(
            timeout=self._timeout, verify=self._verify_ssl
        ) as client:
            response = client.post(step.token_url, data=payload)
        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise AuthFlowError(
                f"refresh_token: token endpoint returned non-JSON: {exc}"
            ) from exc
        if "access_token" not in data:
            raise AuthFlowError(
                f"refresh_token: token endpoint did not return access_token "
                f"(status={response.status_code})"
            )
        if step.save_as:
            self._variables[step.save_as] = data["access_token"]
        self._variables["access_token"] = data["access_token"]
        if "refresh_token" in data:
            self._variables["refresh_token"] = data["refresh_token"]
        result.headers["Authorization"] = f"Bearer {data['access_token']}"

    def _do_validate(
        self,
        step: AuthFlowStep,
        result: AuthFlowResult,
        cookies: dict[str, str],
    ) -> None:
        if not step.url:
            raise AuthFlowError("validate step requires a url")
        url = self._render(step.url) or step.url
        headers = self._render_headers(step.headers)
        if "Authorization" in result.headers:
            headers.setdefault("Authorization", result.headers["Authorization"])
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        with httpx.Client(
            timeout=self._timeout, verify=self._verify_ssl
        ) as client:
            response = client.get(url, headers=headers)
        if response.status_code == step.expect_status:
            result.validated = True
            return
        result.validated = False
        result.failure_reason = (
            f"validate: {url} returned {response.status_code} "
            f"(expected {step.expect_status})"
        )
        raise AuthFlowError(result.failure_reason)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _capture_cookies(
        self, response: httpx.Response, cookies: dict[str, str]
    ) -> None:
        for cookie in response.cookies.jar:
            cookies[cookie.name] = cookie.value

    def _render_form_body(self, body: dict[str, Any]) -> dict[str, str]:
        return {k: self._render(str(v)) or "" for k, v in body.items()}

    def _render_json_body(self, body: dict[str, Any]) -> dict[str, Any]:
        rendered: dict[str, Any] = {}
        for k, v in body.items():
            if isinstance(v, str):
                rendered[k] = self._render(v) or v
            else:
                rendered[k] = v
        return rendered


_STEP_FIELDS = frozenset(
    {
        "step",
        "url",
        "method",
        "body",
        "body_type",
        "headers",
        "from",
        "from_step",
        "pattern",
        "jsonpath",
        "name",
        "save_as",
        "expect_status",
        "token_url",
        "client_id",
        "client_secret",
        "scope",
    }
)


def _resolve_jsonpath(data: Any, path: str) -> Any:
    """Tiny JSONPath resolver supporting ``a.b.c`` and ``a[0]`` syntax.

    Deliberately minimal — enough to navigate typical OAuth/token
    responses without taking a dependency on ``jsonpath-ng``.
    """
    if not path:
        return data
    cursor: Any = data
    token_re = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
    for match in token_re.finditer(path):
        key, idx = match.group(1), match.group(2)
        if cursor is None:
            return None
        if key is not None:
            if isinstance(cursor, Mapping):
                cursor = cursor.get(key)
            else:
                return None
        elif idx is not None:
            try:
                cursor = cursor[int(idx)]
            except (IndexError, TypeError, ValueError):
                return None
    return cursor


# Public re-export so callers can do ``from src.execution.auth_flow_runner import
# urlencode``. Kept private otherwise to avoid polluting the public API.
def urlencode(data: dict[str, str]) -> str:  # pragma: no cover - thin shim
    from urllib.parse import urlencode as _urlencode

    return _urlencode(data)


__all__ = [
    "AuthFlowError",
    "AuthFlowRunner",
    "AuthFlowStep",
    "AuthFlowResult",
]
