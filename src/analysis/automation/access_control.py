"""Automated authorization bypass detection.

Inspired by Autorize Burp extension but fully automated.
Tests endpoints with different auth contexts and compares responses.
"""

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int, str], Awaitable[None] | None]


@dataclass
class EnforcementResult:
    endpoint: str
    method: str
    original_status: int
    test_status: int
    original_length: int
    test_length: int
    result: str
    test_context: str
    details: str = ""


class AccessControlAnalyzer:
    """Automated authorization bypass detection.

    Inspired by Autorize Burp extension but fully automated.
    Tests endpoints with different auth contexts and compares responses.
    """

    BYPASSED = "bypassed"
    ENFORCED = "enforced"
    PARTIAL = "partial"

    AUTH_HEADERS = [
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "jwt",
        "bearer",
        "session",
    ]

    ENFORCEMENT_CODES = {401, 403, 302, 301}

    def __init__(self, http_client: Any = None) -> None:
        self.http_client = http_client
        self._results: list[EnforcementResult] = []

    def check_endpoints(self, endpoints: list[dict[str, Any]]) -> list[EnforcementResult]:
        """Backward-compatible sync wrapper for endpoint analysis.

        Older call sites used a synchronous `check_endpoints` method. Keep this
        contract stable so stale call sites fail less destructively during refactors.
        """
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop is not None and running_loop.is_running():
            raise RuntimeError(
                "check_endpoints cannot be called from a running event loop; "
                "use 'await analyze_endpoints(...)' instead"
            )
        return asyncio.run(self.analyze_endpoints(endpoints))

    async def analyze_endpoints(
        self,
        endpoints: list[dict[str, Any]],
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> list[EnforcementResult]:
        """Analyze all discovered endpoints for authorization issues."""
        results: list[EnforcementResult] = []
        total = sum(1 for endpoint in endpoints if str(endpoint.get("url", "") or "").strip())
        processed = 0

        for endpoint in endpoints:
            url = endpoint.get("url", "")
            method = endpoint.get("method", "GET")
            original_response = endpoint.get("response", {})
            original_headers = endpoint.get("request_headers", {})

            if not url:
                continue

            method = str(method or "GET").upper()
            if not isinstance(original_response, dict):
                original_response = {}
            if not isinstance(original_headers, dict):
                original_headers = {}

            result = await self._test_no_auth(url, method, original_response, original_headers)
            if result:
                results.append(result)

            result = await self._test_invalid_token(
                url, method, original_response, original_headers
            )
            if result:
                results.append(result)

            processed += 1
            await self._notify_progress(
                progress_callback,
                processed=processed,
                total=total,
                url=url,
            )

        self._results = results
        return results

    async def _test_no_auth(
        self,
        url: str,
        method: str,
        original_response: dict[str, Any],
        original_headers: dict[str, str],
    ) -> EnforcementResult | None:
        """Test endpoint with all auth headers removed."""
        if not self.http_client:
            return None

        clean_headers = {
            k: v for k, v in original_headers.items() if k.lower() not in self.AUTH_HEADERS
        }

        try:
            response = await self._make_request(url, method=method, headers=clean_headers)
            if not isinstance(response, dict):
                return None
            return self._compare_responses(url, method, original_response, response, "no_auth")
        except Exception as exc:
            logger.debug("Failed to test %s without auth: %s", url, exc)
            return None

    async def _test_invalid_token(
        self,
        url: str,
        method: str,
        original_response: dict[str, Any],
        original_headers: dict[str, str],
    ) -> EnforcementResult | None:
        """Test endpoint with an invalid/expired token."""
        if not self.http_client:
            return None

        test_headers = dict(original_headers)
        test_headers["Authorization"] = "Bearer invalid-token-expired-12345"

        try:
            response = await self._make_request(url, method=method, headers=test_headers)
            if not isinstance(response, dict):
                return None
            return self._compare_responses(
                url, method, original_response, response, "invalid_token"
            )
        except Exception as exc:
            logger.debug("Failed to test %s with invalid token: %s", url, exc)
            return None

    async def _make_request(
        self,
        url: str,
        *,
        method: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        """Call sync or async HTTP clients and normalize response payloads."""
        if not self.http_client:
            return None
        request_fn = getattr(self.http_client, "request", None)
        if not callable(request_fn):
            return None

        async def _call_async() -> Any:
            try:
                return await request_fn(method, url, headers=headers)
            except TypeError:
                return await request_fn(url, method=method, headers=headers)

        def _call_sync() -> Any:
            try:
                return request_fn(method, url, headers=headers)
            except TypeError:
                return request_fn(url, method=method, headers=headers)

        if inspect.iscoroutinefunction(request_fn):
            response = await _call_async()
        else:
            response = await asyncio.to_thread(_call_sync)
            if inspect.isawaitable(response):
                response = await response
        return await self._normalize_response(response)

    async def _notify_progress(
        self,
        progress_callback: ProgressCallback | None,
        *,
        processed: int,
        total: int,
        url: str,
    ) -> None:
        if progress_callback is None:
            return
        result = progress_callback(processed, total, url)
        if inspect.isawaitable(result):
            await result

    async def _normalize_response(self, response: Any) -> dict[str, Any] | None:
        if response is None:
            return None
        if isinstance(response, dict):
            return response

        status_code = int(getattr(response, "status_code", getattr(response, "status", 0)) or 0)
        headers_obj = getattr(response, "headers", {})
        if isinstance(headers_obj, dict):
            headers = dict(headers_obj)
        elif hasattr(headers_obj, "items"):
            headers = dict(headers_obj.items())
        else:
            headers = {}

        body = ""
        text_value = getattr(response, "text", None)
        if isinstance(text_value, str):
            body = text_value
        elif callable(text_value):
            text_result = text_value()
            if inspect.isawaitable(text_result):
                text_result = await text_result
            body = str(text_result or "")

        return {
            "status_code": status_code,
            "headers": headers,
            "body": body,
            "body_text": body,
        }

    def _compare_responses(
        self,
        endpoint: str,
        method: str,
        original: dict[str, Any],
        test: dict[str, Any],
        context: str,
    ) -> EnforcementResult | None:
        """Compare original and test responses using Autorize algorithm."""
        original_status = original.get("status_code", 0)
        test_status = test.get("status_code", 0)
        original_content = str(original.get("body") or original.get("body_text") or "")
        test_content = str(test.get("body") or test.get("body_text") or "")
        original_length = len(original_content) if isinstance(original_content, str) else 0
        test_length = len(test_content) if isinstance(test_content, str) else 0

        if original_status != test_status:
            if test_status in self.ENFORCEMENT_CODES:
                result = self.ENFORCED
                details = f"Status changed from {original_status} to {test_status}"
            else:
                result = self.PARTIAL
                details = (
                    f"Status changed from {original_status} to {test_status} (not enforcement code)"
                )
        else:
            if original_content == test_content:
                result = self.BYPASSED
                details = f"Identical response ({original_length} bytes) with {context}"
            elif self._content_similarity(original_content, test_content) > 0.9:
                result = self.PARTIAL
                details = f"Highly similar responses ({original_length} vs {test_length} bytes)"
            else:
                result = self.PARTIAL
                details = f"Different content ({original_length} vs {test_length} bytes)"

        return EnforcementResult(
            endpoint=endpoint,
            method=method,
            original_status=original_status,
            test_status=test_status,
            original_length=original_length,
            test_length=test_length,
            result=result,
            test_context=context,
            details=details,
        )

    def _content_similarity(self, content1: str, content2: str) -> float:
        """Calculate content similarity (0.0 to 1.0)."""
        if not content1 or not content2:
            return 0.0

        words1 = set(content1.lower().split())
        words2 = set(content2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        return len(intersection) / len(union) if union else 0.0

    def get_bypassed_endpoints(self) -> list[EnforcementResult]:
        """Get all endpoints with authorization bypasses."""
        return [r for r in self._results if r.result == self.BYPASSED]

    def get_enforcement_summary(self) -> dict[str, Any]:
        """Get summary of enforcement status across all endpoints."""
        total = len(self._results)
        bypassed = len(self.get_bypassed_endpoints())
        enforced = len([r for r in self._results if r.result == self.ENFORCED])
        partial = len([r for r in self._results if r.result == self.PARTIAL])

        return {
            "total_tests": total,
            "bypassed": bypassed,
            "enforced": enforced,
            "partial": partial,
            "bypass_rate": bypassed / total if total > 0 else 0,
        }
