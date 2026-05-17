"""Session management for HTTP request authentication and cookie handling.

Provides Session and SessionRegistry classes for managing authentication state,
cookies, and headers across multiple HTTP requests in the testing pipeline.
"""

from dataclasses import dataclass, field

from src.core.models import Request


def _header_name_map(headers: dict[str, str]) -> dict[str, str]:
    """Build a lowercase-to-original-case mapping for HTTP header names.

    Args:
        headers: Dictionary of header name-value pairs.

    Returns:
        Dictionary mapping lowercase header names to their original casing.
    """
    return {str(name).lower(): name for name in headers}


def _parse_cookie_header(raw_cookie: str) -> dict[str, str]:
    """Parse a Cookie header string into individual cookie name-value pairs.

    Args:
        raw_cookie: Raw Cookie header value (semicolon-separated key=value pairs).

    Returns:
        Dictionary of cookie names to values.
    """
    parsed: dict[str, str] = {}
    for chunk in str(raw_cookie or "").split(";"):
        segment = chunk.strip()
        if not segment or "=" not in segment:
            continue
        key, value = segment.split("=", 1)
        name = key.strip()
        if not name:
            continue
        parsed[name] = value.strip()
    return parsed


@dataclass
class Session:
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    auth_token: str = ""
    role: str = ""
    identity: str = ""

    def attach(self, request: Request) -> Request:
        headers = dict(request.headers)
        header_names = _header_name_map(headers)
        for key, value in self.headers.items():
            if str(key).lower() not in header_names:
                headers[key] = value
                header_names[str(key).lower()] = key
        if self.auth_token and "authorization" not in header_names:
            headers["Authorization"] = f"Bearer {self.auth_token}"
            header_names["authorization"] = "Authorization"
        if self.cookies:
            existing_cookie_name = header_names.get("cookie")
            existing_cookie_value = (
                headers.get(existing_cookie_name, "") if existing_cookie_name else ""
            )
            # Fix #225: Request cookies override session cookies.
            request_cookies = _parse_cookie_header(existing_cookie_value)
            merged_cookies = {**self.cookies, **request_cookies}
            # Fix #226: Do not sort cookies alphabetically as it can break some servers.
            # Preserve the insertion order.
            cookie_value = "; ".join(f"{key}={value}" for key, value in merged_cookies.items())
            if cookie_value:
                cookie_key = existing_cookie_name or "Cookie"
                headers[cookie_key] = cookie_value
        return Request(
            method=request.method,
            url=request.url,
            headers=headers,
            params=dict(request.params),
            body=request.body,
            timeout_seconds=request.timeout_seconds,
        )


@dataclass
class SessionRegistry:
    sessions: dict[str, Session] = field(default_factory=dict)
    active: str = "default"

    def ensure(self, key: str) -> Session:
        normalized = str(key or "default").strip() or "default"
        existing = self.sessions.get(normalized)
        if existing is not None:
            return existing
        created = Session()
        self.sessions[normalized] = created
        return created

    def switch(self, key: str) -> Session:
        session = self.ensure(key)
        self.active = str(key or "default").strip() or "default"
        return session

    def current(self) -> Session:
        return self.ensure(self.active)
