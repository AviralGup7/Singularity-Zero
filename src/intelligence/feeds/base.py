"""Base feed connector with shared configuration and HTTP client lifecycle.

Provides an abstract base class for all threat intelligence feed connectors
with async HTTP client management via httpx, Pydantic configuration models,
retry logic, and standardized error handling.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Self

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def _parse_retry_after_seconds(raw_value: str | None, fallback: float) -> float:
    """Parse Retry-After header into seconds with safe floor."""
    if not raw_value:
        return max(1.0, fallback)
    text = str(raw_value).strip()
    try:
        return max(1.0, float(text))
    except (TypeError, ValueError):
        pass
    try:
        retry_at = datetime.fromisoformat(text.replace("Z", "+00:00"))
        seconds = (retry_at - datetime.now(UTC)).total_seconds()
        return max(1.0, seconds)
    except (TypeError, ValueError):
        return max(1.0, fallback)


class FeedConfig(BaseModel):
    """Base configuration for threat intelligence feed connectors.

    Attributes:
        api_key: API key for authentication.
        base_url: Base URL for the API endpoint.
        timeout_seconds: Request timeout in seconds.
        max_retries: Maximum number of retry attempts on failure.
        retry_delay_seconds: Delay between retries in seconds.
        verify_ssl: Whether to verify SSL certificates.
        user_agent: Custom User-Agent header value.
        extra_headers: Additional HTTP headers to include in requests.
    """

    api_key: str = Field(..., min_length=1, description="API key for the feed service")
    base_url: str = Field(..., min_length=1, description="Base URL for the API")
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    retry_delay_seconds: float = Field(default=1.0, gt=0)
    verify_ssl: bool = Field(default=True)
    user_agent: str = Field(default="CyberSecurityPipeline/1.0")
    extra_headers: dict[str, str] = Field(default_factory=dict)


class FeedError(Exception):
    """Exception raised for feed connector errors."""

    def __init__(
        self, message: str, status_code: int | None = None, response_body: str | None = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class FeedRateLimitError(FeedError):
    """Exception raised when the feed API rate limit is exceeded."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class BaseFeedConnector(ABC):
    """Abstract base class for threat intelligence feed connectors.

    Manages an async httpx client with connection pooling, automatic retries,
    and standardized error handling. Subclasses must implement the
    ``get_client_name`` method and provide feed-specific query methods.

    Attributes:
        config: Feed configuration instance.
        _client: Async httpx client instance (lazy-initialized).
    """

    def __init__(self, config: FeedConfig) -> None:
        self.config = config
        self._client: httpx.AsyncClient | None = None

    @property
    @abstractmethod
    def client_name(self) -> str:
        """Return the name of the feed service."""
        ...

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client.

        Returns:
            Configured httpx.AsyncClient instance.
        """
        if self._client is None or self._client.is_closed:
            headers = {
                "User-Agent": self.config.user_agent,
                "Accept": "application/json",
            }
            if self.config.extra_headers:
                headers.update(self.config.extra_headers)

            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=httpx.Timeout(self.config.timeout_seconds),
                verify=self.config.verify_ssl,
                headers=headers,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
            logger.debug("Initialized HTTP client for %s", self.client_name)

        return self._client

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.debug("Closed HTTP client for %s", self.client_name)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        await self.close()

    async def _request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Execute an HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Request URL path (relative to base_url).
            params: Query parameters.
            json_body: JSON request body.
            headers: Additional headers for this request.

        Returns:
            httpx.Response instance.

        Raises:
            FeedRateLimitError: If the API rate limit is exceeded.
            FeedError: If the request fails after all retries.
        """
        import asyncio

        client = await self._get_client()

        for attempt in range(self.config.max_retries + 1):
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    headers=headers,
                )

                if response.status_code == 429:
                    retry_after = _parse_retry_after_seconds(
                        response.headers.get("Retry-After"),
                        self.config.retry_delay_seconds,
                    )
                    logger.warning(
                        "Rate limited by %s, retrying after %.1fs",
                        self.client_name,
                        retry_after,
                    )
                    raise FeedRateLimitError(
                        f"Rate limit exceeded for {self.client_name}",
                        retry_after=retry_after,
                    )

                if response.status_code >= 500 and attempt < self.config.max_retries:
                    delay = self.config.retry_delay_seconds * (2**attempt)
                    logger.warning(
                        "Server error %d from %s, retry %d/%d after %.1fs",
                        response.status_code,
                        self.client_name,
                        attempt + 1,
                        self.config.max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue

                return response

            except FeedRateLimitError as exc:
                if attempt < self.config.max_retries:
                    delay = (
                        max(1.0, float(exc.retry_after))
                        if exc.retry_after is not None
                        else max(1.0, self.config.retry_delay_seconds * (2**attempt))
                    )
                    await asyncio.sleep(delay)
                    continue
                raise
            except httpx.RequestError as exc:
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay_seconds * (2**attempt)
                    logger.warning(
                        "Request error to %s, retry %d/%d after %.1fs: %s",
                        self.client_name,
                        attempt + 1,
                        self.config.max_retries,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    continue
                raise FeedError(
                    f"Request to {self.client_name} failed after {self.config.max_retries + 1} attempts: {exc}",
                ) from exc

        assert False, "unreachable"  # noqa: RET503

    async def _get(self, url: str, params: dict[str, Any] | None = None) -> httpx.Response:
        return await self._request("GET", url, params=params)

    async def _post(
        self,
        url: str,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self._request("POST", url, json_body=json_body, headers=headers)
