from unittest.mock import patch

import httpx
import pytest

from src.recon.waf_cdn_detector import (
    CDN_WAF_PATTERNS,
    _analyze_response,
    build_waf_cdn_report,
    detect_waf_cdn,
)


class TestWafCdnDetector:
    def test_analyze_response_cloudflare_headers(self):
        url = "https://example.com"
        headers = {"CF-Ray": "12345", "Server": "cloudflare"}
        resp = httpx.Response(
            200, headers=headers, content=b"Hello", request=httpx.Request("GET", url)
        )
        findings = _analyze_response(url, resp)

        assert len(findings) > 0
        cf_finding = next(f for f in findings if f["provider"] == "Cloudflare")
        assert cf_finding["detection_method"] == "headers"
        assert cf_finding["confidence"] == 0.9

    def test_analyze_response_akamai_cookies(self):
        url = "https://example.com"
        # Akamai uses 'abck' cookie
        headers = {"Set-Cookie": "abck=val; Domain=example.com"}
        resp = httpx.Response(
            200, headers=headers, content=b"Hello", request=httpx.Request("GET", url)
        )
        findings = _analyze_response(url, resp)

        assert len(findings) > 0
        akamai_finding = next(f for f in findings if f["provider"] == "Akamai")
        assert akamai_finding["detection_method"] == "cookies"
        assert akamai_finding["confidence"] == 0.8

    def test_analyze_response_aws_waf_body(self):
        url = "https://example.com"
        resp = httpx.Response(403, content=b"blocked by AWS WAF", request=httpx.Request("GET", url))
        findings = _analyze_response(url, resp)

        assert len(findings) > 0
        aws_finding = next(f for f in findings if f["provider"] == "AWS WAF")
        assert aws_finding["detection_method"] == "body"
        assert aws_finding["confidence"] == 0.7

    def test_analyze_response_multiple_indicators(self):
        url = "https://example.com"
        headers = {"X-Amz-Cf-Id": "req-id"}
        # Cloudfront uses cookies too
        headers["Set-Cookie"] = "CloudFront-Policy=xyz"
        resp = httpx.Response(
            200, headers=headers, content=b"Hello", request=httpx.Request("GET", url)
        )
        findings = _analyze_response(url, resp)

        cf_finding = next(f for f in findings if f["provider"] == "AWS CloudFront")
        assert cf_finding["detection_method"] == "headers+cookies"
        assert cf_finding["confidence"] == 1.0

    @pytest.mark.asyncio
    async def test_detect_waf_cdn_orchestration(self):
        url1 = "https://site1.com"
        url2 = "https://site2.com"

        mock_resp1 = httpx.Response(
            200, headers={"CF-Ray": "ray1"}, request=httpx.Request("GET", url1)
        )
        mock_resp2 = httpx.Response(
            200, headers={"X-Served-By": "fastly"}, request=httpx.Request("GET", url2)
        )

        with (
            patch("httpx.AsyncClient.get") as mock_get,
            patch("src.recon.waf_cdn_detector.is_safe_url", return_value=True),
        ):
            mock_get.side_effect = [mock_resp1, mock_resp2]

            results = await detect_waf_cdn([url1, url2], active_probe=False)

            # CF-Ray header matches multiple Cloudflare variants; X-Served-By matches Fastly
            assert len(results) == 4  # 3 Cloudflare variants + 1 Fastly
            providers = {r["provider"] for r in results}
            assert "Cloudflare" in providers
            assert "Fastly" in providers

    @pytest.mark.asyncio
    async def test_detect_waf_cdn_empty(self):
        assert await detect_waf_cdn([]) == []

    @pytest.mark.asyncio
    async def test_detect_waf_cdn_request_error(self):
        url = "https://fail.com"

        with patch("httpx.AsyncClient.get") as mock_get:
            mock_get.side_effect = httpx.RequestError("fail")

            results = await detect_waf_cdn([url])
            assert len(results) == 0

    def test_build_waf_cdn_report(self):
        findings = [
            {"url": "site1.com", "provider": "Cloudflare", "confidence": 0.9},
            {"url": "site2.com", "provider": "Cloudflare", "confidence": 0.9},
            {"url": "site3.com", "provider": "Akamai", "confidence": 0.8},
        ]

        report = build_waf_cdn_report(findings)
        assert report["total_urls_tested"] == 3
        assert report["urls_protected"] == 3
        assert "Cloudflare" in report["unique_providers"]
        assert "Akamai" in report["unique_providers"]
        assert report["by_provider"]["Cloudflare"]["count"] == 2
        assert report["by_provider"]["Akamai"]["count"] == 1

    def test_all_patterns_defined(self):
        # Sanity check that all patterns have keys
        for provider, patterns in CDN_WAF_PATTERNS.items():
            assert "headers" in patterns
            assert "cookies" in patterns
            assert "body" in patterns
