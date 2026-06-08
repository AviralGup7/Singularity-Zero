"""Workflow-and-stateful fuzzer for multi-step attack chains.

Extends the legacy stateful fuzzer with:
- directed endpoint-transition graphs (OpenAPI or sitemap-backed)
- valid-sequence mutation fuzzing across transitions
- state-consistency checking (balance, coupon, privilege)
- optional Playwright-driven browser replay for JS-heavy flows
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

import httpx

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.core.models import Request
from src.core.session import Session, SessionRegistry
from src.core.utils.url_validation import is_safe_url_with_dns_check

logger = logging.getLogger(__name__)

_STATE_CHAIN_MAX_STEPS = 20

csrf_token_re = re.compile(r"name=[\"']csrf_token[\"']\s+value=[\"']([^\"']+)[\"']", re.IGNORECASE)
csrf_header_re = re.compile(r"X-CSRF-Token:\s*([^\s]+)", re.IGNORECASE)
csrf_meta_re = re.compile(r"<meta\s+name=[\"']csrf-token[\"']\s+content=[\"']([^\"']+)[\"']", re.IGNORECASE)

try:
    import playwright  # noqa: F401

    _PLAYWRIGHT_AVAILABLE: bool = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


class EndpointNode:
    def __init__(self, endpoint_id: str, path: str, method: str = "GET") -> None:
        self.endpoint_id = endpoint_id
        self.path = path
        self.method = method.upper()
        self.transitions: dict[str, EndpointNode] = {}

    def __repr__(self) -> str:
        return f"EndpointNode({self.method} {self.path})"

    def __hash__(self) -> int:
        return hash((self.endpoint_id, self.method, self.path))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EndpointNode):
            return NotImplemented
        return self.endpoint_id == other.endpoint_id and self.method == other.method and self.path == other.path


class WorkflowFuzzer:
    """Directed-graph-based workflow fuzzer."""

    def __init__(self, max_steps: int = _STATE_CHAIN_MAX_STEPS) -> None:
        self.max_steps = max_steps
        self.nodes: dict[str, EndpointNode] = {}
        self._edge_signatures: set[str] = set()

    def build_graph_from_openapi(self, spec: dict[str, Any]) -> None:
        """Parse an OpenAPI 3.x spec and build a transition graph."""
        paths = spec.get("paths") or {}
        for path, methods in paths.items():
            for method in ("get", "post", "put", "patch", "delete"):
                if method not in methods:
                    continue
                node_id = f"{method.upper()} {path}"
                self.nodes.setdefault(node_id, EndpointNode(endpoint_id=node_id, path=path, method=method.upper()))

        param_sets: dict[str, set[str]] = {}
        for node_id, node in self.nodes.items():
            raw = paths.get(node.path, {})
            params: set[str] = set()
            for source in ("parameters", "query", "path", "body"):
                params.update(
                    p.get("name", "")
                    for p in (raw.get(node.method.lower()) or {}).get(source, [])
                    if isinstance(p, dict)
                )
            param_sets[node_id] = {p.lower() for p in params if p}

        node_ids = list(self.nodes.keys())
        for i, left_id in enumerate(node_ids):
            for right_id in node_ids[i + 1 :]:
                shared = param_sets.get(left_id, set()) & param_sets.get(right_id, set())
                if shared:
                    self.nodes[left_id].transitions[right_id] = self.nodes[right_id]
                    self.nodes[right_id].transitions[left_id] = self.nodes[left_id]

    def build_graph_from_sitemap(self, urls: list[str]) -> None:
        """Heuristically link URLs by parameter overlap."""

        def _params(url: str) -> set[str]:
            return {k.lower() for k in httpx.URL(url).params}

        url_sets: dict[str, set[str]] = {}
        for url in urls:
            key = endpoint_signature(url)
            url_sets.setdefault(key, set()).update(_params(url))

        items = list(url_sets.items())
        for i, (lk, lp) in enumerate(items):
            for rk, rp in items[i + 1 :]:
                if lp & rp:
                    lid = f"GET {lk.split('|')[1]}"
                    rid = f"GET {rk.split('|')[1]}"
                    left = self.nodes.setdefault(lid, EndpointNode(endpoint_id=lid, path=lk.split("|")[1], method="GET"))
                    right = self.nodes.setdefault(rid, EndpointNode(endpoint_id=rid, path=rk.split("|")[1], method="GET"))
                    if rid not in left.transitions:
                        left.transitions[rid] = right
                    if lid not in right.transitions:
                        right.transitions[lid] = left

    async def fuzz_transition(
        self,
        from_endpoint: str,
        to_endpoint: str,
        valid_sequence: list[dict[str, Any]],
        *,
        client: httpx.AsyncClient,
        session: Session,
        timeout_seconds: float = 5.0,
    ) -> list[dict[str, Any]]:
        """Mutate parameter values from a known-valid sequence and replay the transition."""
        findings: list[dict[str, Any]] = []
        base_payload = valid_sequence[-1] if valid_sequence else {}
        mutations = self._mutate_payload(base_payload)

        for mutation in mutations:
            combined = {**base_payload, **mutation.get("fields", {})}
            url = to_endpoint
            method = combined.pop("_method", "POST").upper()
            if method in {"GET", "HEAD"}:
                url = str(httpx.URL(to_endpoint).copy_with(params=combined)) if combined else to_endpoint

            req = session.attach(
                Request(
                    method=method,
                    url=url,
                    body=httpx.QueryParams(combined).encode() if combined else None,
                    timeout_seconds=int(timeout_seconds),
                )
            )
            try:
                resp = await client.request(req.method, req.url, headers=req.headers, content=req.body, timeout=timeout_seconds)
            except Exception as exc:
                logger.debug("Transition fuzz request failed: %s", exc)
                continue

            if resp.status_code >= 500:
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_base_key": endpoint_base_key(url),
                        "endpoint_type": classify_endpoint(url),
                        "issues": ["workflow_transition_server_error"],
                        "probe_type": "workflow_fuzzer",
                        "severity": "medium",
                        "confidence": 0.75,
                        "evidence": {
                            "from_endpoint": from_endpoint,
                            "to_endpoint": to_endpoint,
                            "mutation": mutation.get("name", "unknown"),
                            "status_code": resp.status_code,
                        },
                    }
                )
        return findings

    @staticmethod
    def _mutate_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
        mutations: list[dict[str, Any]] = []
        for key, value in payload.items():
            if isinstance(value, str) and value:
                mutations.append({"name": f"bitflip_{key}", "fields": {key: _bitflip(value)}})
                mutations.append({"name": f"empty_{key}", "fields": {key: ""}})
                mutations.append({"name": f"overflow_{key}", "fields": {key: "A" * 8192}})
            if isinstance(value, (int, float)):
                mutations.append({"name": f"negative_{key}", "fields": {key: -value}})
                mutations.append({"name": f"zero_{key}", "fields": {key: 0}})
            mutations.append({"name": f"injection_{key}", "fields": {key: "' OR '1'='1"}})
        return mutations

    def detect_inconsistencies(
        self,
        pre_state: dict[str, Any],
        post_state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Cross-check pre/post state and return Finding-shaped dicts."""
        findings: list[dict[str, Any]] = []
        url = str(post_state.get("url") or pre_state.get("url", ""))

        pre_balance = _num(pre_state.get("balance"))
        post_balance = _num(post_state.get("balance"))
        refund_amount = _num(post_state.get("refund_amount", 0))
        if pre_balance is not None and post_balance is not None:
            expected = pre_balance + refund_amount
            if post_balance > expected:
                findings.append(
                    {
                        "url": url,
                        "category": "business_logic",
                        "title": "Negative balance after refund",
                        "severity": "high",
                        "confidence": 0.85,
                        "evidence": {
                            "pre_balance": pre_balance,
                            "post_balance": post_balance,
                            "refund_amount": refund_amount,
                            "expected": expected,
                        },
                    }
                )

        pre_coupons = _int_seq(pre_state.get("coupons_used"))
        post_coupons = _int_seq(post_state.get("coupons_used"))
        if pre_coupons is not None and post_coupons is not None:
            applied = set(pre_coupons) & set(post_coupons)
            if len(applied) > 1:
                findings.append(
                    {
                        "url": url,
                        "category": "business_logic",
                        "title": "Duplicate coupon redemption detected",
                        "severity": "high",
                        "confidence": 0.80,
                        "evidence": {
                            "duplicate_coupons": sorted(applied),
                        },
                    }
                )

        pre_role = str(pre_state.get("role", "")).lower()
        post_role = str(post_state.get("role", "")).lower()
        if pre_role == "user" and post_role in {"admin", "superuser", "root"}:
            findings.append(
                {
                    "url": url,
                    "category": "business_logic",
                    "title": "Privilege escalation detected",
                    "severity": "critical",
                    "confidence": 0.90,
                    "evidence": {
                        "pre_role": pre_role,
                        "post_role": post_role,
                    },
                }
            )
        return findings

    async def replay_with_browser(
        self,
        endpoint: str,
        state: dict[str, Any],
        playwright_page: Any,
    ) -> list[dict[str, Any]]:
        """Drive a JS-heavy workflow step via Playwright."""
        if not _PLAYWRIGHT_AVAILABLE:
            logger.debug("Playwright not available — skipping browser replay for %s", endpoint)
            return []
        try:
            await playwright_page.goto(endpoint, wait_until="domcontentloaded", timeout=10_000)
            for selector, value in (state.get("form_fields") or {}).items():
                try:
                    await playwright_page.fill(selector, str(value))
                except Exception:
                    pass
            if state.get("submit_selector"):
                try:
                    await playwright_page.click(state["submit_selector"])
                except Exception:
                    pass
            content = await playwright_page.content()
            return [
                {
                    "url": endpoint,
                    "endpoint_key": endpoint_signature(endpoint),
                    "endpoint_base_key": endpoint_base_key(endpoint),
                    "endpoint_type": classify_endpoint(endpoint),
                    "issues": ["browser_replay_completed"],
                    "probe_type": "workflow_fuzzer",
                    "severity": "info",
                    "confidence": 0.60,
                    "evidence": {
                        "content_length": len(content),
                        "state_keys": sorted((state or {}).keys()),
                    },
                }
            ]
        except Exception as exc:
            logger.debug("playwright replay failed: %s", exc)
            return []

    async def fuzz_workflow(
        self,
        priority_urls: list[dict[str, Any]],
        response_cache: ResponseCache | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        session: Session | None = None,
        timeout_seconds: float = 5.0,
        limit: int = 12,
    ) -> list[dict[str, Any]]:
        """Run the workflow fuzzer against a list of candidate URLs."""
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        close_client = client is None

        if client is None:
            client = httpx.AsyncClient(timeout=timeout_seconds)

        if session is None:
            session = SessionRegistry().ensure("workflow_fuzzer")

        for item in priority_urls:
            if len(findings) >= limit:
                break
            url = str(item.get("url", "") if isinstance(item, dict) else item).strip()
            if not url or not is_safe_url_with_dns_check(url):
                continue
            endpoint_key = endpoint_signature(url)
            if endpoint_key in seen:
                continue
            seen.add(endpoint_key)

            try:
                base_resp = await client.get(url, timeout=timeout_seconds)
                self._record_edge(url, base_resp, endpoint_key)
            except Exception as exc:
                logger.debug("workflow fuzz base request failed for %s: %s", url, exc)
                continue

            if response_cache and base_resp.status_code in {401, 403}:
                cached = response_cache.get(url)
                if cached:
                    findings.extend(self._extract_csrf_findings(url, str(cached.get("body_text", "")), endpoint_key))

        if close_client:
            await client.aclose()
        return findings[:limit]

    def _record_edge(self, url: str, response: httpx.Response, endpoint_key: str) -> None:
        body_hash = hashlib.md5(response.text[:4096].encode("utf-8", errors="ignore")).hexdigest()[:8]
        signature = f"wf:{endpoint_key}:{response.status_code}:{len(response.text)}:{body_hash}"
        self._edge_signatures.add(signature)

    @staticmethod
    def _extract_csrf_findings(url: str, body: str, endpoint_key: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if csrf_meta_re.search(body) or csrf_token_re.search(body):
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": ["workflow_csrf_token_present"],
                    "probe_type": "workflow_fuzzer",
                    "severity": "medium",
                    "confidence": 0.70,
                    "evidence": {"token_found": True},
                }
            )
        return findings


def _bitflip(value: str) -> str:
    if not value:
        return "A"
    byte_arr = bytearray(value.encode("utf-8", errors="ignore"))
    if byte_arr:
        byte_arr[0] ^= 0x01
    return byte_arr.decode("utf-8", errors="ignore")


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_seq(value: Any) -> list[int] | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        out: list[int] = []
        for item in value:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                pass
        return out or None
    try:
        return [int(value)]
    except (TypeError, ValueError):
        return None
