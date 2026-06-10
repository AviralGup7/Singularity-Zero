import logging
import re
import secrets
from typing import Any
from enum import Enum

import httpx

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.models import Request
from src.core.session import Session, SessionRegistry
from src.core.utils.url_validation import is_safe_url_with_dns_check

logger = logging.getLogger(__name__)

_csrf_token_re = re.compile(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', re.IGNORECASE)
_csrf_header_re = re.compile(r'X-CSRF-Token:\s*([^\s]+)', re.IGNORECASE)
_csrf_meta_re = re.compile(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE)
_STATE_CHAIN_MAX_STEPS = 5


class StateType(str, Enum):
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class StateNode:
    """A node in the state machine graph representing an application state."""

    def __init__(self, state_id: str, state_type: StateType = StateType.UNKNOWN,
                 url: str = "", method: str = "GET", body: str = "",
                 headers: dict[str, str] | None = None,
                 response_indicators: list[str] | None = None) -> None:
        self.state_id = state_id
        self.state_type = state_type
        self.url = url
        self.method = method
        self.body = body
        self.headers = headers or {}
        self.response_indicators = response_indicators or []
        self.transitions: list[tuple[str, str]] = []  # (action_label, next_state_id)


class StateMachineModel:
    """Formal state machine for multi-step fuzzing workflows.

    States represent application states (login, dashboard, admin panel)
    and transitions represent actions (login POST, API call) that move
    between states. The fuzzer explores each transition with mutations
    and validates that the expected state was reached.
    """

    def __init__(self) -> None:
        self.states: dict[str, StateNode] = {}
        self.initial_state: str = ""
        self._state_values: dict[str, Any] = {}  # runtime state values (balance, coupon, role)

    def add_state(self, node: StateNode) -> None:
        self.states[node.state_id] = node
        if not self.initial_state:
            self.initial_state = node.state_id

    def add_transition(self, from_state: str, action: str, to_state: str) -> None:
        if from_state in self.states:
            self.states[from_state].transitions.append((action, to_state))

    def set_initial_state(self, state_id: str) -> None:
        self.initial_state = state_id

    def get_state_value(self, key: str) -> Any:
        return self._state_values.get(key)

    def set_state_value(self, key: str, value: Any) -> None:
        self._state_values[key] = value


def build_graph_from_openapi(openapi_spec: dict[str, Any]) -> StateMachineModel:
    """Build a state machine from an OpenAPI specification.

    Parses paths and methods to create states (one per endpoint) and
    transitions (links between endpoints that share parameters or are
    in the same tag group).
    """
    model = StateMachineModel()
    paths = openapi_spec.get("paths", {})
    first_state = True

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() in ("get", "post", "put", "delete", "patch"):
                state_id = f"{method.upper()}:{path}"
                tags = details.get("tags", [])
                state_type = StateType.ADMIN if "admin" in [t.lower() for t in tags] else StateType.UNKNOWN
                node = StateNode(
                    state_id=state_id,
                    state_type=state_type,
                    url=path,
                    method=method.upper(),
                    response_indicators=tags,
                )
                model.add_state(node)
                if first_state:
                    model.set_initial_state(state_id)
                    first_state = False

    # Build transitions: link endpoints within the same tag group
    for state_id, node in model.states.items():
        for other_id, other_node in model.states.items():
            if state_id != other_id and set(node.response_indicators) & set(other_node.response_indicators):
                model.add_transition(state_id, f"transition_to_{other_id}", other_id)

    return model


def build_graph_from_har(har_data: dict[str, Any]) -> StateMachineModel:
    """Build a state machine from HAR file entries.

    Parses request/response pairs to create states and transitions
    based on the actual request flow observed in the HAR.
    """
    model = StateMachineModel()
    entries = har_data.get("log", {}).get("entries", [])
    prev_state_id = ""

    for i, entry in enumerate(entries[:50]):
        req = entry.get("request", {})
        resp = entry.get("response", {})
        method = req.get("method", "GET")
        url = req.get("url", "")
        status = resp.get("status", 0)

        state_id = f"{method}:{url}:{status}:{i}"
        state_type = StateType.AUTHENTICATED if status == 200 else StateType.UNKNOWN
        node = StateNode(
            state_id=state_id,
            state_type=state_type,
            url=url,
            method=method,
            response_indicators=[str(status)],
        )
        model.add_state(node)

        if prev_state_id:
            model.add_transition(prev_state_id, f"request_{i}", state_id)
        else:
            model.set_initial_state(state_id)
        prev_state_id = state_id

    return model


async def run_stateful_campaign_with_machine(
    model: StateMachineModel,
    base_url: str,
    client: httpx.AsyncClient | None = None,
    *,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    """Execute a fuzzing campaign guided by a state machine model.

    Traverses each transition in the model, mutating the request body
    and parameters at each step, and validates that the expected state
    was reached by checking response indicators.
    """
    findings: list[dict[str, Any]] = []
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds)
        close_client = True

    try:
        current_state_id = model.initial_state
        visited: set[str] = set()
        max_transitions = 20

        for _ in range(max_transitions):
            if current_state_id not in model.states:
                break
            if current_state_id in visited:
                break
            visited.add(current_state_id)

            current_node = model.states[current_state_id]
            for action, next_state_id in current_node.transitions:
                if next_state_id not in model.states:
                    continue
                next_node = model.states[next_state_id]
                full_url = base_url.rstrip("/") + current_node.url

                if not is_safe_url_with_dns_check(full_url):
                    logger.warning("Stateful fuzzer: URL failed SSRF safety check, skipping: %s", full_url)
                    continue

                # Send the request
                try:
                    resp = await client.request(
                        method=current_node.method,
                        url=full_url,
                        headers=current_node.headers or {},
                        content=current_node.body or None,
                        timeout=timeout_seconds,
                    )
                except Exception:
                    continue

                if resp is None:
                    continue

                # Check if response indicators match expected state
                body_lower = resp.text.lower()
                matched_indicators = [
                    ind for ind in next_node.response_indicators
                    if ind.lower() in body_lower
                ]

                # Check for state inconsistencies
                if resp.status_code >= 500:
                    findings.append({
                        "technique": "state_machine_error",
                        "from_state": current_state_id,
                        "to_state": next_state_id,
                        "action": action,
                        "status": resp.status_code,
                        "severity": "medium",
                        "hint": f"Transition {action} caused server error",
                    })

                if matched_indicators:
                    current_state_id = next_state_id
                    break

        # Check for state consistency issues (balance/role changes)
        balance = model.get_state_value("balance")
        role = model.get_state_value("role")
        if balance is not None:
            try:
                check_resp = await client.get(
                    base_url + "/api/user",
                    timeout=timeout_seconds,
                )
                if check_resp is not None:
                    import json
                    try:
                        user_data = json.loads(check_resp.text)
                        new_balance = user_data.get("balance")
                        if new_balance is not None and new_balance != balance:
                            findings.append({
                                "technique": "state_consistency_violation",
                                "expected_balance": balance,
                                "actual_balance": new_balance,
                                "severity": "high",
                                "hint": "Balance changed during state transitions",
                            })
                    except Exception as exc:
                        logger.warning("Operation failed in stateful_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
            except Exception as exc:
                logger.warning("Operation failed in stateful_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001

    finally:
        if close_client:
            await client.aclose()

    return findings


class StatefulFuzzingSession:
    def __init__(self, session: Session, max_steps: int = _STATE_CHAIN_MAX_STEPS) -> None:
        self.session = session
        self.max_steps = max_steps
        self.step_history: list[dict[str, Any]] = []
        self.csrf_token: str | None = None

    def _extract_csrf_token(self, response: httpx.Response) -> str | None:
        body = response.text
        headers_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())

        match = _csrf_meta_re.search(body)
        if match:
            return match.group(1)

        match = _csrf_token_re.search(body)
        if match:
            return match.group(1)

        match = _csrf_header_re.search(headers_text)
        if match:
            return match.group(1)

        return None

    async def _execute_stateful_chain(self, url: str, session: Session, *, client: httpx.AsyncClient, timeout_seconds: float = 5.0) -> list[dict[str, Any]]:
        self.step_history = []
        self.csrf_token = None

        request0 = session.attach(Request(method="GET", url=url, timeout_seconds=int(timeout_seconds)))
        response0 = await client.get(request0.url, headers=request0.headers, timeout=timeout_seconds)

        step0: dict[str, Any] = {
            "step": 0,
            "url": url,
            "method": "GET",
            "status": response0.status_code,
        }
        self.step_history.append(step0)

        self.csrf_token = self._extract_csrf_token(response0)
        step1: dict[str, Any] = {
            "step": 1,
            "url": url,
            "token_found": self.csrf_token is not None,
            "token": self.csrf_token,
        }
        self.step_history.append(step1)

        mutations: list[tuple[str, str]] = []
        if self.csrf_token:
            byte_arr = bytearray(self.csrf_token.encode("utf-8", errors="ignore"))
            if len(byte_arr) > 0:
                idx = 0
                bit = secrets.randbelow(8)
                byte_arr[idx] ^= 1 << bit
                mutations.append(("bit_flip", byte_arr.decode("utf-8", errors="ignore")))
            mutations.append(("empty", ""))
            mutations.append(("injection", "<script>alert(1)</script>"))
        else:
            mutations.append(("none", ""))

        for mut_name, mut_token in mutations:
            if len(self.step_history) >= self.max_steps:
                break

            headers: dict[str, str] = {}
            body_payload: str | None = None
            if mut_token:
                headers["X-CSRF-Token"] = mut_token
                body_payload = f"csrf_token={mut_token}"

            request = session.attach(
                Request(
                    method="POST",
                    url=url,
                    headers=headers,
                    body=body_payload,
                    timeout_seconds=int(timeout_seconds),
                )
            )
            response = await client.post(
                request.url,
                headers=request.headers,
                content=request.body,
                timeout=timeout_seconds,
            )

            step_entry: dict[str, Any] = {
                "step": len(self.step_history),
                "url": url,
                "method": "POST",
                "mutation": mut_name,
                "token": mut_token if mut_token else None,
                "status": response.status_code,
            }
            self.step_history.append(step_entry)

            if mut_token and response.status_code in {200, 201}:
                step_entry["finding"] = "stateful_csrf_bypass"

            if mut_token:
                set_cookie = response.headers.get("set-cookie", "")
                if set_cookie and "session" in set_cookie.lower():
                    step_entry["session_cookie"] = set_cookie
                    step_entry["finding"] = "stateful_session_fixation"

            base_status = response0.status_code
            existing_state_errors = sum(1 for e in self.step_history if e.get("finding") == "stateful_state_error")
            if base_status < 500 and response.status_code >= 500 and existing_state_errors == 0:
                error_step: dict[str, Any] = {
                    "step": len(self.step_history),
                    "url": url,
                    "finding": "stateful_state_error",
                    "base_status": base_status,
                    "mutated_status": response.status_code,
                }
                self.step_history.append(error_step)

        return self.step_history

    async def run_stateful_fuzzing_campaign(self, url: str, client: httpx.AsyncClient | None = None, *, session: Session | None = None, timeout_seconds: float = 5.0, max_steps: int = 5) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if not is_safe_url_with_dns_check(url):
            logger.warning("Stateful fuzzer: URL failed SSRF safety check, skipping: %s", url)
            return findings

        active_session = session if session is not None else SessionRegistry().ensure("fuzzer")

        close_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=timeout_seconds, verify=True)
            close_client = True

        endpoint_key = endpoint_signature(url)
        ebase = endpoint_base_key(url)
        etype = classify_endpoint(url)

        try:
            await self._execute_stateful_chain(url, active_session, client=client, timeout_seconds=timeout_seconds)
            issues: list[str] = []
            for entry in self.step_history:
                finding = entry.get("finding")
                if finding and finding not in issues:
                    issues.append(finding)

            if issues:
                severity = "high" if "stateful_csrf_bypass" in issues else "medium"
                findings.append({
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": ebase,
                    "endpoint_type": etype,
                    "issues": issues,
                    "probe_type": "stateful_fuzzer",
                    "severity": severity,
                    "confidence": 0.85,
                    "evidence": {
                        "step_history": self.step_history,
                    },
                })
        except Exception as e:
            logger.warning("Stateful fuzzer campaign failed for %s: %s", url, e)
        finally:
            if close_client:
                await client.aclose()

        return findings


async def run_stateful_fuzzing_campaign(url: str, client: httpx.AsyncClient | None = None, *, session: Session | None = None, timeout_seconds: float = 5.0, max_steps: int = 5) -> list[dict[str, Any]]:
    active_session = session if session is not None else SessionRegistry().ensure("fuzzer")
    fuzzer = StatefulFuzzingSession(session=active_session, max_steps=max_steps)
    return await fuzzer.run_stateful_fuzzing_campaign(url, client=client, session=active_session, timeout_seconds=timeout_seconds, max_steps=max_steps)
