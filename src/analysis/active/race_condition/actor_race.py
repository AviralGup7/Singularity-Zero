"""Multi-user actor race-condition testing module.

Part B implementation:
- ``ActorRaceTester`` fires two concurrent requests from two independent
  authenticated clients and compares post-race state.
- Supports classic double-submit race testing.
- ``Finding`` dataclass models structured findings returned by tester methods.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

try:
    import httpx
except Exception:  # pragma: no cover - optional dependency guard
    httpx = None  # type: ignore[assignment]


@dataclass(frozen=True)
class Finding:
    finding_type: str
    actor: str
    resource_id: str
    field: str | None = None
    value_before: Any = None
    value_after: Any = None
    delta: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ActorRaceTester:
    """Race-condition tester using two independent authenticated actors.

    ``credential_vault`` must expose at least two credential sets with differing
    privilege levels.  Supported interfaces:

    * ``vault.credentials() -> list[dict[str, Any]]``
    * ``vault.get_credentials_for(resource_id: str, action: str) -> list[dict[str, Any]]``

    Each credential dict contains at minimum ``token`` / ``cookie`` and a
    ``privilege`` level such as ``"user"`` or ``"admin"``.
    """

    def __init__(self, credential_vault: Any) -> None:
        self._vault = credential_vault

    def _resolve_credentials(
        self, resource_id: str, action: str
    ) -> list[dict[str, Any]]:
        if hasattr(self._vault, "get_credentials_for"):
            return list(self._vault.get_credentials_for(resource_id, action) or [])
        if hasattr(self._vault, "credentials"):
            return list(self._vault.credentials())
        if isinstance(self._vault, dict):
            return [self._vault]
        return []

    def _pick_two(
        self, resource_id: str, action: str = "race"
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        creds = self._resolve_credentials(resource_id, action)
        if len(creds) < 2:
            raise ValueError(
                "credential_vault must provide at least 2 credentials. "
                f"Got {len(creds)} credential set(s)."
            )
        return creds[0], creds[1]

    @staticmethod
    def _build_client(credential: dict[str, Any]) -> httpx.Client:
        headers: dict[str, str] = {}
        cookie_map: dict[str, str] = {}
        token = (
            credential.get("token")
            or credential.get("access_token")
            or credential.get("session_token")
            or ""
        )
        if token:
            scheme = credential.get("auth_scheme") or "Bearer"
            headers["Authorization"] = f"{scheme} {token}"
        for key, value in credential.items():
            if "cookie" in key.lower():
                cookie_map[str(key)] = str(value)
        return httpx.Client(
            headers=headers if headers else None,
            cookies=cookie_map if cookie_map else None,
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=10.0, read=15.0, write=10.0, pool=5.0
            ),
        )

    def race_action(
        self,
        actor_a_token: str,
        actor_b_token: str,
        resource_id: str,
        action: str,
        url_template: str,
        method: str = "POST",
        extra_headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Send two concurrent requests from two independent ``httpx.Client`` instances.

        Each client carries its own Authorization header / cookie jar, so the server
        sees two distinct authenticated sessions. Returns the raw response dicts
        ``(actor_a_response, actor_b_response)``.
        """
        if httpx is None:
            raise ImportError(
                "httpx is required for ActorRaceTester. "
                "Install httpx==0.28.0 to use this feature."
            )

        actor_a = {"token": actor_a_token, "auth_scheme": "Bearer", "actor_name": "actor_a"}
        actor_b = {"token": actor_b_token, "auth_scheme": "Bearer", "actor_name": "actor_b"}

        url = url_template.format(resource_id=resource_id, action=action)

        def _fire(credential: dict[str, Any]) -> dict[str, Any] | None:
            client = self._build_client(credential)
            try:
                req_headers = dict(extra_headers or {})
                if (
                    body is not None
                    and isinstance(body, str)
                    and "Content-Type" not in req_headers
                ):
                    req_headers["Content-Type"] = "application/json"
                with client:
                    resp = client.request(
                        method.upper(), url, headers=req_headers, content=body
                    )
                return {
                    "status_code": resp.status_code,
                    "body_text": resp.text,
                    "headers": dict(resp.headers),
                    "final_url": str(resp.url),
                    "actor": credential.get("actor_name", "unknown"),
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "status_code": None,
                    "body_text": None,
                    "headers": {},
                    "actor": credential.get("actor_name", "unknown"),
                    "error": str(exc),
                }

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _paired() -> tuple[dict[str, Any], dict[str, Any]]:
            return tuple(await asyncio.gather(  # type: ignore[return-value]
                asyncio.to_thread(_fire, actor_a),
                asyncio.to_thread(_fire, actor_b),
                return_exceptions=False,
            ))

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_paired(), loop)
            return future.result(timeout=60)
        return asyncio.run(_paired())

    def compare_post_race_state(
        self,
        actor_a_state: dict[str, Any],
        actor_b_state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Compare post-race state dicts and return structured ``Finding`` dicts.

        Compares numeric fields (balances, quantities, credits) and privilege
        levels. Any divergence with a delta is returned.
        """
        findings: list[dict[str, Any]] = []
        comparable_numeric = {
            "balance",
            "new_balance",
            "remaining",
            "amount",
            "resource_count",
            "resources",
            "quantity",
            "qty",
            "credits",
            "wallet",
            "total",
        }
        comparable_privilege = {"privilege", "privilege_level", "role", "tier"}
        shared_numeric = comparable_numeric & set(actor_a_state) & set(actor_b_state)
        for key in sorted(shared_numeric):
            a_val = actor_a_state.get(key)
            b_val = actor_b_state.get(key)
            if isinstance(a_val, (int, float)) and isinstance(b_val, (int, float)):
                if a_val != b_val:
                    delta = (a_val - b_val) if a_val is not None and b_val is not None else None
                    findings.append(
                        {
                            "type": "actor_state_divergence",
                            "field": key,
                            "actor_a_value": a_val,
                            "actor_b_value": b_val,
                            "delta": delta,
                            "privilege_leak": (
                                "actor_a_advantage"
                                if delta is not None and delta > 0
                                and key in {"balance", "credits", "amount", "wallet", "total"}
                                else "actor_b_advantage"
                                if delta is not None and delta < 0
                                and key in {"balance", "credits", "amount", "wallet", "total"}
                                else None
                            ),
                        }
                    )
        shared_privilege = comparable_privilege & set(actor_a_state) & set(actor_b_state)
        privilege_rank = {"user": 0, "member": 1, "premium": 2, "moderator": 3, "admin": 4}
        for key in sorted(shared_privilege):
            a_raw = actor_a_state.get(key)
            b_raw = actor_b_state.get(key)
            if isinstance(a_raw, str) and isinstance(b_raw, str):
                a_rank = privilege_rank.get(a_raw.lower(), -1)
                b_rank = privilege_rank.get(b_raw.lower(), -1)
                if a_rank != b_rank:
                    findings.append(
                        {
                            "type": "privilege_escalation_race",
                            "field": key,
                            "actor_a_value": a_raw,
                            "actor_b_value": b_raw,
                            "actor_a_rank": a_rank,
                            "actor_b_rank": b_rank,
                        }
                    )
        return findings

    def test_double_submit(
        self,
        actor_a: dict[str, Any],
        actor_b: dict[str, Any],
        payment_auth_id: str,
        url_template: str,
    ) -> list[dict[str, Any]]:
        """Classic double-submit race: both actors claim the same ``payment_auth_id``.

        Both actors POST the same ``payment_auth_id`` concurrently. If the backend
        does not atomically de-queue the authorization, one or both requests may
        succeed.
        """
        url = url_template.format(payment_auth_id=payment_auth_id)
        findings: list[dict[str, Any]] = []

        def _submit(actor: dict[str, Any]) -> dict[str, Any] | None:
            client = self._build_client(actor)
            try:
                with client:
                    resp = client.post(url, json={"payment_auth_id": payment_auth_id})
                return {
                    "status_code": resp.status_code,
                    "body_text": resp.text,
                    "headers": dict(resp.headers),
                    "actor": actor.get("actor_name", "unknown"),
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "status_code": None,
                    "body_text": None,
                    "actor": actor.get("actor_name", "unknown"),
                    "error": str(exc),
                }

        if httpx is None:
            raise ImportError(
                "httpx is required for ActorRaceTester. "
                "Install httpx==0.28.0 to use this feature."
            )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _coro() -> list[dict[str, Any]]:
            return list(await asyncio.gather(  # type: ignore[return-value]
                asyncio.to_thread(_submit, actor_a),
                asyncio.to_thread(_submit, actor_b),
                return_exceptions=False,
            ))

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_coro(), loop)
            responses = future.result(timeout=60)
        else:
            responses = asyncio.run(_coro())

        successes = [r for r in responses if int(r.get("status_code") or 0) < 400]
        if len(successes) > 1:
            findings.append(
                {
                    "type": "double_submit_race",
                    "payment_auth_id": payment_auth_id,
                    "successful_claims": len(successes),
                    "status": "vulnerable",
                    "risk": "Both actors successfully claimed the same payment_auth_id.",
                    "responses": successes,
                }
            )
        elif len(successes) == 1:
            findings.append(
                {
                    "type": "possible_double_submit_race",
                    "payment_auth_id": payment_auth_id,
                    "successful_claims": 1,
                    "status": "uncertain",
                    "risk": (
                        "Payment authorization was claimed once; further testing "
                        "with additional repetitions is recommended."
                    ),
                    "responses": successes,
                }
            )
        else:
            findings.append(
                {
                    "type": "double_submit_race",
                    "payment_auth_id": payment_auth_id,
                    "successful_claims": 0,
                    "status": "not_observed",
                    "risk": "No actor successfully claimed the payment authorization.",
                    "responses": responses,
                }
            )
        return findings
