"""CredentialVault for capturing, rotating, and injecting credentials across probes."""

from __future__ import annotations

import base64
import dataclasses
import logging
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

COOKIE_HEADER_PATTERN = re.compile(r"([^;,\s]+)=([^;,\s]*)(?:\s*;\s*|\s*$|(?=,))", re.IGNORECASE)
SET_COOKIE_PATTERN = re.compile(r"Set-Cookie:\s*([^=]+)=([^;]*)(?:;[^:]*)*(?:\r?\n|$)", re.IGNORECASE)


def _default_expiry() -> datetime | None:
    return datetime.now(UTC) + timedelta(hours=12)


def _now() -> datetime:
    return datetime.now(UTC)


@dataclasses.dataclass(slots=True)
class CapturedCredential:
    credential_id: str
    name: str
    type: str
    value: str
    scope_url: str | None
    expires_at: datetime | None


class CredentialVault:
    def __init__(self) -> None:
        self._credentials: dict[str, CapturedCredential] = {}
        self._lock = threading.Lock()
        self.sessions_by_privilege: dict[str, CapturedCredential | None] = {
            "user": None,
            "editor": None,
            "admin": None,
        }
        self._scan_host_netlocs: set[str] = set()
        self._saml_assertion_history: list[dict[str, Any]] = []

    @property
    def scan_host_netlocs(self) -> set[str]:
        return self._scan_host_netlocs.copy()

    @scan_host_netlocs.setter
    def scan_host_netlocs(self, value: set[str]) -> None:
        self._scan_host_netlocs = set(value)

    def add_scan_host(self, url: str) -> None:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                self._scan_host_netlocs.add(parsed.hostname.lower())
        except Exception:  # noqa: S110
            pass

    def capture_from_response(self, response: dict[str, Any]) -> list[CapturedCredential]:
        """Extract credentials from HTTP response headers (Set-Cookie, Authorization)."""
        if not response:
            return []
        captured: list[CapturedCredential] = []
        scope_url = (
            response.get("final_url")
            or response.get("url")
            or response.get("requested_url")
            or ""
        )
        scope_netloc = _safe_netloc(scope_url) or ""
        self.add_scan_host(scope_url)

        headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
        saw_auth = False
        for raw_header_value in headers.values():
            for match in SET_COOKIE_PATTERN.finditer(raw_header_value + "\n"):
                name = match.group(1).strip()
                value = match.group(2).strip()
                if name or value:
                    saw_auth = True
                if name.lower() in {"authorization"}:
                    continue
                captured.append(
                    self._store_credential(
                        name=name,
                        cred_type="cookie",
                        value=value,
                        scope_url=scope_url,
                        scope_netloc=scope_netloc,
                        expires_at=_default_expiry(),
                    )
                )

        if "authorization" in headers:
            auth_value = headers["authorization"].strip()
            saw_auth = True
            cred_type = "bearing" if auth_value.lower().startswith("bearer ") else "authorization"
            captured.append(
                self._store_credential(
                    name=headers.get("authorization", "authorization"),
                    cred_type=cred_type,
                    value=auth_value,
                    scope_url=scope_url,
                    scope_netloc=scope_netloc,
                    expires_at=_default_expiry(),
                )
            )

        if "set-cookie" in headers:
            saw_auth = True
            for name, value in _parse_set_cookie(headers["set-cookie"]):
                captured.append(
                    self._store_credential(
                        name=name,
                        cred_type="cookie",
                        value=value,
                        scope_url=scope_url,
                        scope_netloc=scope_netloc,
                        expires_at=_default_expiry(),
                    )
                )

        request_body = response.get("request_body") or response.get("body_text") or ""
        if isinstance(request_body, str) and "samlresponse" in request_body.lower():
            saw_auth = True
            for match in re.finditer(r"(?i)sam[lr]response=([^&\s]+)", request_body):
                raw = match.group(1)
                try:
                    decoded_value = base64.b64decode(raw).decode("utf-8", errors="replace")
                except Exception:  # noqa: S110
                    decoded_value = raw
                captured.append(
                    self._store_credential(
                        name="samlresponse",
                        cred_type="samlresponse",
                        value=decoded_value,
                        scope_url=scope_url,
                        scope_netloc=scope_netloc,
                        expires_at=_default_expiry(),
                    )
                )
                self._record_saml_assertion(captured[-1], response)

        if saw_auth and not captured:
            for key, value in headers.items():
                if key in ("authorization", "set-cookie"):
                    captured.append(
                        self._store_credential(
                            name=key,
                            cred_type=key,
                            value=value,
                            scope_url=scope_url,
                            scope_netloc=scope_netloc,
                            expires_at=_default_expiry(),
                        )
                    )

        self._reconcile_session_map()
        return captured

    def rotate_token(self, credential_id: str, refresh_url: str, refresh_token: str) -> CapturedCredential | None:
        with self._lock:
            credential = self._credentials.get(credential_id)
        if not credential:
            return None
        payload = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if credential.type == "authorization":
            payload["client_id"] = credential.name
            payload["client_secret"] = ""
        try:
            resp = requests.post(refresh_url, data=payload, headers={"Accept": "application/json"}, timeout=10)
        except (requests.TooManyRedirects, requests.RequestException):
            return credential
        new_access_token = _extract_access_token(resp)
        if not new_access_token:
            return credential
        updated = dataclasses.replace(credential, value=new_access_token, expires_at=_parse_expires_at(resp) or _default_expiry())
        with self._lock:
            self._credentials[credential_id] = updated
        self._reconcile_session_map()
        return updated

    def get_credential_for_url(self, url: str) -> CapturedCredential | None:
        with self._lock:
            candidates = list(self._credentials.values())
        if not candidates:
            return None
        parsed_target = urlparse(url)
        target_netloc = (parsed_target.hostname or "").lower()
        target_path = parsed_target.path or ""
        best = None
        best_score = -1.0
        for cred in candidates:
            scope_netloc = _safe_netloc(cred.scope_url)
            if not scope_netloc or scope_netloc != target_netloc:
                continue
            score = len(scope_netloc)
            if cred.scope_url and target_path.startswith(cred.scope_url.split(scope_netloc, 1)[1] or "/"):
                score += 1_000.0
            if score > best_score:
                best = cred
                best_score = score
        if not best:
            return None
        best_expires = best.expires_at.replace(tzinfo=UTC) if best.expires_at and best.expires_at.tzinfo is None else best.expires_at
        if best_expires and best_expires < _now():
            return None
        return best

    def inject_into_request(self, request: dict[str, Any], url: str) -> None:
        if not isinstance(request, dict) or not isinstance(request.get("headers"), dict):
            return
        credential = self.get_credential_for_url(url)
        if not credential:
            return
        headers = request["headers"]
        if credential.type == "cookie":
            existing = headers.get("Cookie", "")
            parts = [part.strip() for part in existing.split(";") if part.strip()] if existing else []
            if credential.value:
                parts.append(f"{credential.name}={credential.value}")
            headers["Cookie"] = "; ".join(parts)
        elif credential.type in {"bearing", "authorization"}:
            headers.setdefault("Authorization", credential.value)
        else:
            headers.setdefault("Authorization", f"Bearer {credential.value}")

    def capture_from_raw_body(self, body: str, url: str) -> list[CapturedCredential]:
        response = {
            "final_url": url,
            "url": url,
            "requested_url": url,
            "headers": {},
            "body_text": body,
            "request_body": body,
        }
        return self.capture_from_response(response)

    def record_saml_assertion(self, saml_response_b64: str, *, source_url: str, request_body: str = "", response_body: str = "") -> CapturedCredential | None:
        encoded = saml_response_b64 if isinstance(saml_response_b64, str) else ""
        try:
            base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:  # noqa: S110
            pass
        pseudo_response = {
            "final_url": source_url,
            "url": source_url,
            "requested_url": source_url,
            "headers": {},
            "body_text": response_body,
            "request_body": request_body,
        }
        captured = self.capture_from_response(pseudo_response)
        return captured[0] if captured else None

    def captured_credentials(self) -> list[CapturedCredential]:
        with self._lock:
            return [dataclasses.replace(credential) for credential in self._credentials.values()]

    def _store_credential(self, name: str, cred_type: str, value: str, scope_url: str, scope_netloc: str, expires_at: datetime | None) -> CapturedCredential:
        credential_id = f"{cred_type}:{name}:{uuid.uuid4().hex[:8]}"
        credential = CapturedCredential(credential_id=credential_id, name=name, type=cred_type, value=value, scope_url=scope_url, expires_at=expires_at)
        with self._lock:
            self._credentials[credential_id] = credential
        return credential

    def _reconcile_session_map(self) -> None:
        mapping = {key: None for key in self.sessions_by_privilege}
        for credential in self._credentials.values():
            privilege = self._privilege_for(credential)
            if privilege and mapping.get(privilege) is None:
                mapping[privilege] = credential
        self.sessions_by_privilege.update(mapping)

    @staticmethod
    def _privilege_for(credential: CapturedCredential) -> str | None:
        lower_name = credential.name.lower()
        lower_value = credential.value.lower()
        lower_type = credential.type.lower()
        if any(keyword in lower_name or keyword in lower_value for keyword in {"admin", "administrator"}):
            return "admin"
        if any(keyword in lower_name or keyword in lower_value for keyword in {"editor", "editorial"}):
            return "editor"
        if lower_type == "samlresponse":
            return "user"
        if lower_type in {"cookie"} and lower_name not in {"sessionid", "sid"}:
            return "user"
        if lower_type in {"bearing", "authorization"}:
            return "user"
        return None

    def _record_saml_assertion(self, credential: CapturedCredential, response: dict[str, Any]) -> None:
        self._saml_assertion_history.append(
            {
                "credential_id": credential.credential_id,
                "scope_url": credential.scope_url,
                "assertion_value": credential.value,
                "captured_at": _now().isoformat(),
                "response_status_code": response.get("status_code"),
                "response_headers": response.get("headers"),
            }
        )

    def saml_assertions(self) -> list[dict[str, Any]]:
        return list(self._saml_assertion_history)


def _safe_netloc(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:  # noqa: S110
        return ""


def _parse_set_cookie(value: str) -> list[tuple[str, str]]:
    return COOKIE_HEADER_PATTERN.findall(value)


def _extract_access_token(response: requests.Response) -> str | None:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return str((payload.get("access_token") or payload.get("accessToken") or payload.get("token")) or "").strip() or None
    except Exception:  # noqa: S110
        pass
    return None


def _parse_expires_at(response: requests.Response) -> datetime | None:
    try:
        payload = response.json()
        if isinstance(payload, dict) and "expires_in" in payload:
            return datetime.now(UTC) + timedelta(seconds=int(payload["expires_in"]))
    except Exception:  # noqa: S110
        pass
    return None
