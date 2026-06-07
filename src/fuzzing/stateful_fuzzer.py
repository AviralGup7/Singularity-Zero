import asyncio
import logging
import re
from typing import Any

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
                bit = 0
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
            if base_status < 500 and response.status_code >= 500 and "stateful_state_error" not in [e.get("finding") for e in self.step_history]:
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
