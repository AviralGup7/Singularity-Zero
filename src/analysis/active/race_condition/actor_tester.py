"""Multi-user actor race-condition tester."""

import asyncio
import logging
from typing import Any

try:
    import httpx
except Exception:  # pragma: no cover - optional dependency guard
    logging.getLogger(__name__).warning("Failed to import httpx", exc_info=True)
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class ActorRaceTester:
    """Race-condition tester using two independent authenticated actors.

    ``credential_vault`` must expose at least two credential sets with differing
    privilege levels.  Typical interfaces:

    * ``vault.credentials() -> list[dict[str, Any]]``
    * ``vault.get_credentials_for(resource_id: str, action: str) -> list[dict[str, Any]]``

    Each credential dict contains at minimum ``token`` / ``cookie`` and a
    ``privilege`` level such as ``"user"`` or ``"admin"``.
    """

    def __init__(self, credential_vault: Any) -> None:
        self.vault = credential_vault

    def _pick_two_credentials(
        self, resource_id: str, action: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        creds = self._resolve_credentials(resource_id, action)
        if len(creds) < 2:
            raise ValueError(
                "Credential vault must provide at least 2 credentials. "
                f"Got {len(creds)} credential(s)."
            )
        return creds[0], creds[1]

    def _resolve_credentials(self, resource_id: str, action: str) -> list[dict[str, Any]]:
        if hasattr(self.vault, "get_credentials_for"):
            creds = self.vault.get_credentials_for(resource_id, action)
            return list(creds or [])
        if hasattr(self.vault, "credentials"):
            return list(self.vault.credentials())
        return [self.vault] if isinstance(self.vault, dict) else []

    def _make_client(self, credential: dict[str, Any]) -> httpx.Client:
        headers: dict[str, str] = {}
        cookie_map: dict[str, str] = {}
        token = (
            credential.get("token")
            or credential.get("access_token")
            or credential.get("session_token")
            or ""
        )
        if token:
            auth_scheme = credential.get("auth_scheme", "Bearer")
            headers["Authorization"] = f"{auth_scheme} {token}"
        for key, value in credential.items():
            if "cookie" in key.lower():
                cookie_map[str(key)] = str(value)
        client = httpx.Client(
            headers=headers if headers else None,
            cookies=cookie_map if cookie_map else None,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0),
        )
        return client

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
        """Fire two concurrent requests from separate client instances.

        Each actor receives its own ``httpx.Client`` with a different cookie jar /
        Authorization header so that the server sees two independent authenticated
        sessions. Returns ``(actor_a_response, actor_b_response)`` dicts.
        """
        actor_a = {"token": actor_a_token, "auth_scheme": "Bearer"}
        actor_b = {"token": actor_b_token, "auth_scheme": "Bearer"}
        url = url_template.format(resource_id=resource_id, action=action)

        def _fire(credential: dict[str, Any]) -> dict[str, Any] | None:
            client = self._make_client(credential)
            try:
                req_body = body
                if (
                    req_body is not None
                    and isinstance(req_body, str)
                    and "Content-Type" not in (extra_headers or {})
                ):
                    req_headers = {"Content-Type": "application/json"}
                    req_headers.update(extra_headers or {})
                else:
                    req_headers = dict(extra_headers or {})
                with client:
                    resp = client.request(
                        method.upper(), url, headers=req_headers, content=req_body
                    )
                return {
                    "status_code": resp.status_code,
                    "body_text": resp.text,
                    "headers": dict(resp.headers),
                    "url": str(resp.url),
                }
            except Exception as exc:  # noqa: BLE001
                return {"status_code": None, "body_text": None, "headers": {}, "error": str(exc)}

        if httpx is None:
            raise ImportError("httpx is required for ActorRaceTester. Install httpx==0.28.0.")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _paired_race() -> tuple[dict[str, Any], dict[str, Any]]:
            coro_a = asyncio.to_thread(_fire, actor_a)
            coro_b = asyncio.to_thread(_fire, actor_b)
            results = await asyncio.gather(coro_a, coro_b)
            return (results[0] or {}, results[1] or {})

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_paired_race(), loop)
            return future.result(timeout=60)
        return asyncio.run(_paired_race())

    def compare_post_race_state(
        self,
        actor_a_state: dict[str, Any],
        actor_b_state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Compare two post-race state dicts and return a list of ``Finding`` dicts.

        State dicts are expected to contain fields such as ``balance``,
        ``privilege``, ``resource_count``, ``quantity`` etc.
        """
        findings: list[dict[str, Any]] = []
        comparable_keys = {
            "balance",
            "privilege",
            "privilege_level",
            "resource_count",
            "resources",
            "quantity",
            "qty",
            "credits",
            "remaining",
            "wallet",
            "amount",
        }
        shared_keys = comparable_keys & set(actor_a_state) & set(actor_b_state)
        for key in sorted(shared_keys):
            a_val = actor_a_state.get(key)
            b_val = actor_b_state.get(key)
            if isinstance(a_val, (int, float)) and isinstance(b_val, (int, float)):
                if a_val != b_val:
                    change_a = a_val - b_val
                    findings.append(
                        {
                            "type": "actor_state_divergence",
                            "field": key,
                            "actor_a_value": a_val,
                            "actor_b_value": b_val,
                            "delta": change_a,
                            "privilege_leak": (
                                "actor_a_advantage"
                                if change_a > 0
                                and key in {"balance", "credits", "amount", "wallet"}
                                else "actor_b_advantage"
                                if change_a < 0
                                else None
                            ),
                        }
                    )
            elif isinstance(a_val, str) and isinstance(b_val, str) and a_val != b_val:
                lower_a = a_val.lower()
                lower_b = b_val.lower()
                privilege_order = {"user": 0, "member": 1, "premium": 2, "moderator": 3, "admin": 4}
                if key in {"privilege", "privilege_level", "role"}:
                    rank_a = privilege_order.get(lower_a, -1)
                    rank_b = privilege_order.get(lower_b, -1)
                    if rank_a != rank_b:
                        findings.append(
                            {
                                "type": "privilege_escalation_race",
                                "field": key,
                                "actor_a_value": a_val,
                                "actor_b_value": b_val,
                                "actor_a_rank": rank_a,
                                "actor_b_rank": rank_b,
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
        """Classic double-submit race: both actors submit the same ``payment_auth_id``.

        Both actors attempt to claim the same payment authorization in parallel.
        If the backend fails to atomically de-queue the payment, one or both
        requests may succeed.
        """
        url = url_template.format(payment_auth_id=payment_auth_id)
        findings: list[dict[str, Any]] = []

        def _submit(actor: dict[str, Any]) -> dict[str, Any] | None:
            client = self._make_client(actor)
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
                return {"status_code": None, "body_text": None, "error": str(exc)}

        if httpx is None:
            raise ImportError("httpx is required for ActorRaceTester.")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _double_submit_coro() -> list[dict[str, Any]]:
            results = await asyncio.gather(
                asyncio.to_thread(_submit, actor_a),
                asyncio.to_thread(_submit, actor_b),
                return_exceptions=False,
            )
            return [r for r in results if r is not None]

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_double_submit_coro(), loop)
            responses = future.result(timeout=60)
        else:
            responses = asyncio.run(_double_submit_coro())

        successes = [r for r in responses if r.get("status_code", 0) < 400]
        if len(successes) > 1:
            findings.append(
                {
                    "type": "double_submit_race",
                    "payment_auth_id": payment_auth_id,
                    "successful_claims": len(successes),
                    "responses": successes,
                    "risk": (
                        "Both actors successfully claimed the same payment_auth_id "
                        "indicating a double-submit race vulnerability."
                    ),
                }
            )
        elif len(successes) == 1:
            findings.append(
                {
                    "type": "possible_double_submit_race",
                    "payment_auth_id": payment_auth_id,
                    "successful_claims": 1,
                    "responses": successes,
                    "risk": (
                        "Payment authorization claimed once; further testing with "
                        "additional repetitions recommended."
                    ),
                }
            )
        return findings
