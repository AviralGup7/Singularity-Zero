"""Burp Collaborator OAST interaction client."""

from __future__ import annotations

import json
import logging
import secrets
import string
import time
from typing import Any
from urllib.parse import urlencode

import urllib3

from src.integrations.burp.burp_oast_types import BurpCollaboratorError, OastInteraction

logger = logging.getLogger(__name__)


_BURP_POLL_ENDPOINT = "poll"
_BURP_REGISTER_ENDPOINT = "register"
_DEFAULT_TIMEOUT = 30


class BurpCollaboratorClient:
    """Minimal Burp Collaborator HTTP API client for OAST polling.

    Does NOT require a running Burp Suite instance — works standalone
    against any Collaborator-compatible HTTP endpoint.
    """

    def __init__(self, server_url: str) -> None:
        self.server_url = server_url.rstrip("/")
        self._pool = urllib3.PoolManager(timeout=urllib3.util.Timeout(connect=10, read=10))

    def generate_oast_payload(self, prefix: str) -> str:
        token = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
        safe_prefix = prefix.strip(".-").lower().replace("_", "-")
        if safe_prefix:
            return f"{safe_prefix}-{token}.{self.server_url.replace('https://', '').replace('http://', '')}"
        return f"{token}.{self.server_url.replace('https://', '').replace('http://', '')}"

    def poll_interactions(self, timeout_seconds: int = _DEFAULT_TIMEOUT) -> list[OastInteraction]:
        deadline = time.monotonic() + timeout_seconds
        interactions: list[OastInteraction] = []
        while time.monotonic() < deadline:
            try:
                raw = self._poll_once()
                for entry in raw:
                    try:
                        interactions.append(self._normalise_entry(entry))
                    except Exception as exc:
                        logger.debug("Failed to normalise collaborator entry: %s", exc)
                if interactions:
                    break
            except Exception as exc:
                logger.debug("Collaborator poll failed: %s", exc)
            time.sleep(2)
        logger.info("Observed %d collaborator interactions", len(interactions))
        return interactions

    def _poll_once(self) -> list[dict[str, Any]]:
        url = f"{self.server_url}/{_BURP_POLL_ENDPOINT}"
        response = self._pool.request("GET", url)
        if response.status >= 400:
            raise BurpCollaboratorError(
                f"Collaborator poll returned HTTP {response.status}"
            )
        try:
            payload = json.loads(response.data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise BurpCollaboratorError("Invalid JSON from collaborator poll") from exc
        if isinstance(payload, dict):
            items = payload.get("interactions") or payload.get("records") or []
        elif isinstance(payload, list):
            items = payload
        else:
            items = []
        return [item for item in items if isinstance(item, dict)]

    def _normalise_entry(self, entry: dict[str, Any]) -> OastInteraction:
        return OastInteraction(
            interaction_id=str(entry.get("id") or entry.get("interaction_id") or ""),
            interaction_type=str(entry.get("type") or entry.get("interaction_type") or "dns"),
            client_ip=str(entry.get("client_ip") or entry.get("source") or entry.get("address") or ""),
            timestamp=str(entry.get("timestamp") or entry.get("time") or ""),
            query_string=entry.get("query") or entry.get("parameters") or {},
            raw_request=str(entry.get("raw_request") or entry.get("request") or ""),
            extra={k: v for k, v in entry.items() if k not in {
                "id", "interaction_id", "type", "interaction_type",
                "client_ip", "source", "address", "timestamp", "time",
                "query", "parameters", "raw_request", "request",
            }},
        )

    def register_payload(self, prefix: str = "pipeline") -> str:
        payload = self.generate_oast_payload(prefix)
        url = f"{self.server_url}/{_BURP_REGISTER_ENDPOINT}"
        params = urlencode({"payload": payload})
        try:
            response = self._pool.urlopen("POST", f"{url}?{params}")
            if response.status >= 400:
                raise BurpCollaboratorError(
                    f"Collaborator register returned HTTP {response.status}"
                )
        except BurpCollaboratorError:
            raise
        except Exception as exc:
            raise BurpCollaboratorError(f"Collaborator register failed: {exc}") from exc
        return payload


__all__ = ["BurpCollaboratorClient"]
