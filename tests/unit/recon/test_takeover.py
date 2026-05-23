"""Unit tests for the subdomain takeover detection module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.pipeline.services.tool_execution import CompletedToolRun
from src.recon.takeover import (
    TAKEOVER_PATTERNS,
    _check_http_indicators,
    _check_single_subdomain,
    _match_cname_pattern,
    _resolve_cname,
    detect_takeover,
)


@pytest.mark.unit
class TestSubdomainTakeover:
    """Unit tests for subdomain takeover adapters and matching logic."""

    @pytest.mark.asyncio
    @patch("src.recon.takeover.run_external_tool", new_callable=AsyncMock)
    async def test_resolve_cname_success(self, mock_run: AsyncMock) -> None:
        """Verify _resolve_cname successfully parses canonical name from nslookup output."""
        mock_run.return_value = CompletedToolRun(
            exit_code=0,
            stdout="sub.example.com    canonical name = vuln-bucket.s3.amazonaws.com.\n",
            stderr="",
            timed_out=False,
        )

        cname = await _resolve_cname("sub.example.com")
        assert cname == "vuln-bucket.s3.amazonaws.com"
        mock_run.assert_called_once()
        inv = mock_run.call_args[0][0]
        assert inv.tool_name == "nslookup"
        assert "sub.example.com" in inv.args

    @pytest.mark.asyncio
    @patch("src.recon.takeover.run_external_tool", new_callable=AsyncMock)
    async def test_resolve_cname_failure(self, mock_run: AsyncMock) -> None:
        """Verify _resolve_cname returns None on non-zero exit code or timeouts."""
        # 1. Non-zero exit code
        mock_run.return_value = CompletedToolRun(
            exit_code=1,
            stdout="",
            stderr="Host not found",
            timed_out=False,
        )
        assert await _resolve_cname("sub.example.com") is None

        # 2. Timeout
        mock_run.return_value = CompletedToolRun(
            exit_code=-1,
            stdout="",
            stderr="",
            timed_out=True,
        )
        assert await _resolve_cname("sub.example.com") is None

        # 3. Exception
        mock_run.side_effect = RuntimeError("Process spawning failed")
        assert await _resolve_cname("sub.example.com") is None

    def test_match_cname_pattern(self) -> None:
        """Verify CNAME pattern matching ignores case and checks suffix matching correctly."""
        assert _match_cname_pattern("bucket.s3.amazonaws.com", ".s3.amazonaws.com") is True
        assert _match_cname_pattern("BUCKET.S3.AMAZONAWS.COM", ".s3.amazonaws.com") is True
        assert _match_cname_pattern("bucket.s4.amazonaws.com", ".s3.amazonaws.com") is False
        assert _match_cname_pattern("s3.amazonaws.com.attacker.com", ".s3.amazonaws.com") is False

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient")
    async def test_check_http_indicators_vulnerable(self, mock_client_cls: MagicMock) -> None:
        """Verify check_http_indicators flags matches when provider patterns are in the response body."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.text = "NoSuchBucket - The specified bucket does not exist."
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client_cls.return_value = mock_client

        indicators = ["NoSuchBucket", "The specified bucket does not exist"]
        matched = await _check_http_indicators("sub.example.com", indicators)

        assert len(matched) == 2
        assert "NoSuchBucket" in matched
        assert "The specified bucket does not exist" in matched

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient")
    async def test_check_http_indicators_safe(self, mock_client_cls: MagicMock) -> None:
        """Verify check_http_indicators returns empty list if no provider indicator is found."""
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.text = "<html><body>Welcome to My Bucket Website</body></html>"
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client_cls.return_value = mock_client

        indicators = ["NoSuchBucket"]
        matched = await _check_http_indicators("sub.example.com", indicators)
        assert len(matched) == 0

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient")
    async def test_check_http_indicators_exceptions(self, mock_client_cls: MagicMock) -> None:
        """Verify check_http_indicators handles HTTP requests failures gracefully."""
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("Connection failed")
        mock_client.__aenter__.return_value = mock_client
        mock_client_cls.return_value = mock_client

        matched = await _check_http_indicators("sub.example.com", ["NoSuchBucket"])
        assert len(matched) == 0

    @pytest.mark.asyncio
    @patch("src.recon.takeover._resolve_cname", new_callable=AsyncMock)
    @patch("src.recon.takeover._check_http_indicators", new_callable=AsyncMock)
    async def test_check_single_subdomain(
        self, mock_check_http: AsyncMock, mock_resolve: AsyncMock
    ) -> None:
        """Verify _check_single_subdomain aggregates CNAME checks and HTTP matching."""
        # 1. CNAME resolution fails
        mock_resolve.return_value = None
        findings = await _check_single_subdomain("sub.example.com", TAKEOVER_PATTERNS)
        assert len(findings) == 0

        # 2. CNAME resolves but does not match any provider pattern
        mock_resolve.return_value = "some-random-domain.com"
        findings = await _check_single_subdomain("sub.example.com", TAKEOVER_PATTERNS)
        assert len(findings) == 0

        # 3. CNAME resolves and matches provider, but HTTP indicators do not match (Not vulnerable)
        mock_resolve.return_value = "mybucket.s3.amazonaws.com"
        mock_check_http.return_value = []
        findings = await _check_single_subdomain("sub.example.com", TAKEOVER_PATTERNS)
        assert len(findings) == 1
        assert findings[0]["subdomain"] == "sub.example.com"
        assert findings[0]["service"] == "AWS S3"
        assert findings[0]["cname"] == "mybucket.s3.amazonaws.com"
        assert findings[0]["vulnerable"] is False

        # 4. CNAME resolves, matches provider, and HTTP indicators match (Vulnerable!)
        mock_check_http.return_value = ["NoSuchBucket"]
        findings = await _check_single_subdomain("sub.example.com", TAKEOVER_PATTERNS)
        assert len(findings) == 1
        assert findings[0]["subdomain"] == "sub.example.com"
        assert findings[0]["vulnerable"] is True
        assert "NoSuchBucket" in findings[0]["indicators_matched"]

    @pytest.mark.asyncio
    @patch("src.recon.takeover._check_single_subdomain", new_callable=AsyncMock)
    async def test_detect_takeover_orchestration(self, mock_check_single: AsyncMock) -> None:
        """Verify detect_takeover coordinates multiple subdomains concurrently and aggregates results."""
        mock_check_single.side_effect = lambda sd, patterns: [
            {
                "subdomain": sd,
                "service": "GitHub Pages",
                "cname": "gh.github.io",
                "vulnerable": True,
            }
        ]

        subdomains = {"sub1.example.com", "sub2.example.com"}
        findings = await detect_takeover(subdomains)

        assert len(findings) == 2
        subdomains_found = {f["subdomain"] for f in findings}
        assert subdomains_found == subdomains
        assert all(f["vulnerable"] for f in findings)

    @pytest.mark.asyncio
    @patch("src.recon.takeover._check_single_subdomain", new_callable=AsyncMock)
    async def test_detect_takeover_exception_resilience(self, mock_check_single: AsyncMock) -> None:
        """Verify detect_takeover continues processing other subdomains when one throws an exception."""

        def mock_check(sd, patterns):
            if sd == "bad.example.com":
                raise RuntimeError("DNS resolve failed completely")
            return [
                {
                    "subdomain": sd,
                    "service": "GitHub Pages",
                    "cname": "gh.github.io",
                    "vulnerable": False,
                }
            ]

        mock_check_single.side_effect = AsyncMock(side_effect=mock_check)

        subdomains = {"bad.example.com", "good.example.com"}
        findings = await detect_takeover(subdomains)

        assert len(findings) == 1
        assert findings[0]["subdomain"] == "good.example.com"
