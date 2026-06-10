"""Unit tests for src.recon.origin_discovery.

Covers:
- expand_origin_patterns (pure)
- OriginDiscovery dataclass and to_dict
- discover_origins_async with all sub-tasks mocked (DNS + SecurityTrails)
- discover_origins_sync wrapper
- discover_origins_for_findings batch entry point
- rank_urls integration with origin_hosts (CDN bypass signal, CDN penalty suppressed,
  origin URLs survive parameter-only and strict-tier filters)
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.recon.origin_discovery import (
    ORIGIN_PREFIXES,
    OriginDiscovery,
    discover_origins_async,
    discover_origins_for_findings,
    discover_origins_sync,
    expand_origin_patterns,
)

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestExpandOriginPatterns:
    def test_returns_all_prefixes(self):
        hosts = expand_origin_patterns("example.com")
        assert len(hosts) == len(ORIGIN_PREFIXES)
        assert "origin.example.com" in hosts
        assert "direct.example.com" in hosts
        assert "backend.example.com" in hosts
        assert "real.example.com" in hosts
        assert "internal.example.com" in hosts
        assert "cname.example.com" in hosts

    def test_invalid_domain_returns_empty(self):
        assert expand_origin_patterns("") == set()
        assert expand_origin_patterns("not a domain") == set()
        # IP-shaped inputs are rejected by domain_validation
        assert expand_origin_patterns("127.0.0.1") == set()
        assert expand_origin_patterns("999.999.999.999") == set()
        # Inputs containing forbidden characters (slash, at sign, port, etc.)
        assert expand_origin_patterns("foo/bar.com") == set()
        assert expand_origin_patterns("foo:80.com") == set()
        assert expand_origin_patterns("foo@bar.com") == set()

    def test_uppercase_and_trailing_dot_normalized(self):
        hosts = expand_origin_patterns("Example.COM.")
        # The function lowercases internally via normalize_domain
        assert "origin.example.com" in hosts
        assert "ORIGIN.example.com" not in hosts


class TestOriginDiscoveryDataclass:
    def test_to_dict_sorts_all_sets(self):
        d = OriginDiscovery(
            domain="example.com",
            candidate_hosts={"b.example.com", "a.example.com"},
            candidate_ips={"9.9.9.9", "1.1.1.1"},
            pattern_hosts={"origin.example.com"},
            mx_hosts={"mail.example.com"},
            ns_hosts={"ns1.example.com"},
            historical_ips={"5.5.5.5"},
            sources_used={"mx", "ns", "patterns"},
        )
        out = d.to_dict()
        assert out["domain"] == "example.com"
        assert out["candidate_hosts"] == ["a.example.com", "b.example.com"]
        assert out["candidate_ips"] == ["1.1.1.1", "9.9.9.9"]
        assert out["pattern_hosts"] == ["origin.example.com"]
        assert out["mx_hosts"] == ["mail.example.com"]
        assert out["ns_hosts"] == ["ns1.example.com"]
        assert out["historical_ips"] == ["5.5.5.5"]
        assert out["sources_used"] == ["mx", "ns", "patterns"]
        assert out["host_count"] == 2
        assert out["ip_count"] == 2

    def test_empty_dataclass(self):
        d = OriginDiscovery(domain="example.com")
        assert d.to_dict() == {
            "domain": "example.com",
            "candidate_hosts": [],
            "candidate_ips": [],
            "pattern_hosts": [],
            "mx_hosts": [],
            "ns_hosts": [],
            "historical_ips": [],
            "sources_used": [],
            "host_count": 0,
            "ip_count": 0,
        }


# ---------------------------------------------------------------------------
# Async orchestrator with mocked sub-tasks
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


class TestDiscoverOriginsAsync:
    def test_all_sources_disabled_returns_empty(self):
        result = _run(
            discover_origins_async(
                "example.com",
                enable_pattern_expansion=False,
                enable_mx_harvest=False,
                enable_ns_harvest=False,
                enable_historical_dns=False,
            )
        )
        assert result.domain == "example.com"
        assert result.candidate_hosts == set()
        assert result.candidate_ips == set()
        assert result.sources_used == set()

    def test_invalid_domain_returns_empty(self):
        result = _run(discover_origins_async("not a domain"))
        assert result.candidate_hosts == set()
        assert result.candidate_ips == set()
        assert result.domain == ""

    def test_pattern_expansion_only(self):
        result = _run(
            discover_origins_async(
                "example.com",
                enable_pattern_expansion=True,
                enable_mx_harvest=False,
                enable_ns_harvest=False,
                enable_historical_dns=False,
            )
        )
        assert "origin.example.com" in result.pattern_hosts
        assert result.candidate_hosts == result.pattern_hosts
        assert result.sources_used == {"patterns"}
        assert result.candidate_ips == set()

    def test_mx_harvest_with_mocked_dns(self):
        # dnspython returns "preference host" pairs; socket-style returns just host.
        # We return the bare-host style here to exercise the defensive split.
        async def fake_query_dns(domain: str, rtype: str, timeout: float) -> list[str]:
            assert rtype == "MX"
            return ["mail.example.com"]

        def fake_resolve_a(host: str) -> list[str]:
            assert host == "mail.example.com"
            return ["203.0.113.10"]

        with (
            patch("src.recon.origin_discovery._query_dns", new=fake_query_dns),
            patch("src.recon.origin_discovery._resolve_a", new=fake_resolve_a),
        ):
            result = _run(
                discover_origins_async(
                    "example.com",
                    enable_pattern_expansion=False,
                    enable_mx_harvest=True,
                    enable_ns_harvest=False,
                    enable_historical_dns=False,
                )
            )
        assert result.mx_hosts == {"mail.example.com"}
        assert "203.0.113.10" in result.candidate_ips
        assert "mail.example.com" in result.candidate_hosts
        assert result.sources_used == {"mx"}

    def test_mx_with_preference_format(self):
        # dnspython returns "preference host" — make sure we still parse it.
        async def fake_query_dns(domain: str, rtype: str, timeout: float) -> list[str]:
            return ["10 mail.example.com", "20 mail2.example.com"]

        def fake_resolve_a(host: str) -> list[str]:
            return [f"203.0.113.{10 if host == 'mail.example.com' else 20}"]

        with (
            patch("src.recon.origin_discovery._query_dns", new=fake_query_dns),
            patch("src.recon.origin_discovery._resolve_a", new=fake_resolve_a),
        ):
            result = _run(
                discover_origins_async(
                    "example.com",
                    enable_pattern_expansion=False,
                    enable_mx_harvest=True,
                    enable_ns_harvest=False,
                    enable_historical_dns=False,
                )
            )
        assert result.mx_hosts == {"mail.example.com", "mail2.example.com"}
        assert result.candidate_ips == {"203.0.113.10", "203.0.113.20"}

    def test_ns_harvest_with_mocked_dns(self):
        async def fake_query_dns(domain: str, rtype: str, timeout: float) -> list[str]:
            assert rtype == "NS"
            return ["ns1.cloudflare.com", "ns2.cloudflare.com"]

        def fake_resolve_a(host: str) -> list[str]:
            return [f"198.51.100.{1 if '1' in host else 2}"]

        with (
            patch("src.recon.origin_discovery._query_dns", new=fake_query_dns),
            patch("src.recon.origin_discovery._resolve_a", new=fake_resolve_a),
        ):
            result = _run(
                discover_origins_async(
                    "example.com",
                    enable_pattern_expansion=False,
                    enable_mx_harvest=False,
                    enable_ns_harvest=True,
                    enable_historical_dns=False,
                )
            )
        assert result.ns_hosts == {"ns1.cloudflare.com", "ns2.cloudflare.com"}
        assert "198.51.100.1" in result.candidate_ips
        assert result.sources_used == {"ns"}

    def test_historical_dns_with_mocked_securitytrails(self):
        async def fake_historical(domain: str, **kwargs: Any) -> list[str]:
            return ["192.0.2.1", "192.0.2.2"]

        with patch(
            "src.recon.origin_discovery.query_securitytrails_historical_a",
            new=fake_historical,
        ):
            result = _run(
                discover_origins_async(
                    "example.com",
                    enable_pattern_expansion=False,
                    enable_mx_harvest=False,
                    enable_ns_harvest=False,
                    enable_historical_dns=True,
                )
            )
        assert result.historical_ips == {"192.0.2.1", "192.0.2.2"}
        assert result.candidate_ips == {"192.0.2.1", "192.0.2.2"}
        assert result.sources_used == {"historical_a"}

    def test_all_sources_combined(self):
        async def fake_query_dns(domain: str, rtype: str, timeout: float) -> list[str]:
            if rtype == "MX":
                return ["mail.example.com"]
            if rtype == "NS":
                return ["ns1.example.com"]
            return []

        def fake_resolve_a(host: str) -> list[str]:
            return [f"203.0.113.{abs(hash(host)) & 0xFF}"]

        async def fake_historical(domain: str, **kwargs: Any) -> list[str]:
            return ["192.0.2.99"]

        with (
            patch("src.recon.origin_discovery._query_dns", new=fake_query_dns),
            patch("src.recon.origin_discovery._resolve_a", new=fake_resolve_a),
            patch(
                "src.recon.origin_discovery.query_securitytrails_historical_a",
                new=fake_historical,
            ),
        ):
            result = _run(discover_origins_async("example.com"))

        # Patterns
        assert "origin.example.com" in result.pattern_hosts
        # MX
        assert "mail.example.com" in result.mx_hosts
        # NS
        assert "ns1.example.com" in result.ns_hosts
        # Historical IPs
        assert "192.0.2.99" in result.historical_ips
        # All four sources marked used
        assert result.sources_used == {"patterns", "mx", "ns", "historical_a"}

    def test_dns_failure_does_not_crash(self):
        async def fake_query_dns(domain: str, rtype: str, timeout: float) -> list[str]:
            raise RuntimeError("resolver down")

        async def fake_historical(domain: str, **kwargs: Any) -> list[str]:
            return ["192.0.2.1"]

        with (
            patch("src.recon.origin_discovery._query_dns", new=fake_query_dns),
            patch(
                "src.recon.origin_discovery.query_securitytrails_historical_a",
                new=fake_historical,
            ),
        ):
            result = _run(discover_origins_async("example.com"))
        # Patterns and historical still work; MX/NS were raised
        assert "origin.example.com" in result.pattern_hosts
        assert result.historical_ips == {"192.0.2.1"}
        assert result.mx_hosts == set()
        assert result.ns_hosts == set()


# ---------------------------------------------------------------------------
# Sync wrapper
# ---------------------------------------------------------------------------


class TestDiscoverOriginsSync:
    def test_sync_wrapper_returns_same_shape(self):
        async def fake_query_dns(domain: str, rtype: str, timeout: float) -> list[str]:
            return ["mail.example.com"]

        def fake_resolve_a(host: str) -> list[str]:
            return ["203.0.113.10"]

        with (
            patch("src.recon.origin_discovery._query_dns", new=fake_query_dns),
            patch("src.recon.origin_discovery._resolve_a", new=fake_resolve_a),
            patch(
                "src.recon.origin_discovery.query_securitytrails_historical_a",
                new=AsyncMock(return_value=[]),
            ),
        ):
            result = discover_origins_sync(
                "example.com",
                enable_pattern_expansion=False,
                enable_mx_harvest=True,
                enable_ns_harvest=False,
                enable_historical_dns=False,
            )
        assert result.mx_hosts == {"mail.example.com"}
        assert "203.0.113.10" in result.candidate_ips


# ---------------------------------------------------------------------------
# Batch entry point
# ---------------------------------------------------------------------------


class TestDiscoverOriginsForFindings:
    def test_empty_findings_returns_empty(self):
        assert discover_origins_for_findings([]) == {}

    def test_low_confidence_findings_skipped(self):
        findings = [
            {
                "url": "https://example.com",
                "provider": "Cloudflare",
                "confidence": 0.5,
            }
        ]
        assert discover_origins_for_findings(findings) == {}

    def test_high_confidence_findings_processed(self):
        findings = [
            {
                "url": "https://example.com",
                "provider": "Cloudflare",
                "confidence": 0.95,
            },
            {
                "url": "https://www.example.com/path",
                "provider": "Cloudflare",
                "confidence": 0.92,
            },
        ]

        # Both findings point to the same root (example.com); we expect
        # the batch entry point to dedupe and call discover_origins_sync
        # exactly once for that root.
        with patch(
            "src.recon.origin_discovery.discover_origins_sync",
            return_value=OriginDiscovery(
                domain="example.com",
                pattern_hosts={"origin.example.com"},
                sources_used={"patterns"},
            ),
        ) as mock_sync:
            results = discover_origins_for_findings(findings)

        assert "example.com" in results
        assert results["example.com"].pattern_hosts == {"origin.example.com"}
        # Only one root to process (dedup)
        assert mock_sync.call_count == 1

    def test_max_domains_cap(self):
        findings = [
            {"url": f"https://n{i}.example{i}.com", "provider": "Cloudflare", "confidence": 0.95}
            for i in range(30)
        ]
        with patch(
            "src.recon.origin_discovery.discover_origins_sync",
            return_value=OriginDiscovery(domain=""),
        ) as mock_sync:
            discover_origins_for_findings(findings, max_domains=5)
        assert mock_sync.call_count == 5

    def test_malformed_url_does_not_crash(self):
        findings = [
            {"url": "", "provider": "Cloudflare", "confidence": 0.95},
            {"url": "not a url", "provider": "Cloudflare", "confidence": 0.95},
        ]
        assert discover_origins_for_findings(findings) == {}


# ---------------------------------------------------------------------------
# rank_urls integration with origin_hosts
# ---------------------------------------------------------------------------


@pytest.fixture
def base_scoring_config() -> dict[str, Any]:
    return {
        "weights": {"api": 3, "auth": 2, "param": 2, "admin": 4},
        "modes": {},
        "contexts": {},
        "custom_keyword_bonus": 2,
    }


@pytest.fixture
def base_filters() -> dict[str, Any]:
    return {"ignore_extensions": [], "priority_keywords": [], "priority_limit": 100}


class TestRankUrlsOriginBypass:
    def test_origin_host_injected_into_pool(self, base_filters, base_scoring_config):
        from src.recon.scoring import rank_urls

        urls = ["https://www.example.com/api?id=1"]
        result = rank_urls(
            urls,
            base_filters,
            base_scoring_config,
            mode="default",
            origin_hosts={"origin.example.com"},
        )
        url_strings = {item["url"] for item in result}
        # The original URL still appears
        assert "https://www.example.com/api?id=1" in url_strings
        # The origin-bypass host was injected
        assert "https://origin.example.com" in url_strings

    def test_origin_host_tagged_with_bypass_signal(self, base_filters, base_scoring_config):
        from src.recon.scoring import rank_urls

        urls = ["https://www.example.com/api?id=1"]
        result = rank_urls(
            urls,
            base_filters,
            base_scoring_config,
            mode="default",
            origin_hosts={"origin.example.com"},
        )
        origin_items = [item for item in result if "origin.example.com" in item["url"]]
        assert len(origin_items) == 1
        assert "origin_bypass" in origin_items[0]["signals"]

    def test_origin_host_survives_parameterless_filter(self, base_filters, base_scoring_config):
        from src.recon.scoring import rank_urls

        # A parameterless URL would normally be filtered out by
        # "if not parameter_names and not signals: continue"
        result = rank_urls(
            [],
            base_filters,
            base_scoring_config,
            mode="default",
            origin_hosts={"origin.example.com"},
        )
        url_strings = {item["url"] for item in result}
        assert "https://origin.example.com" in url_strings

    def test_cdn_penalty_suppressed_for_origin_host(self, base_filters, base_scoring_config):
        from src.recon.scoring import rank_urls

        waf_findings = [
            {
                "url": "https://origin.example.com",
                "provider": "Cloudflare",
                "confidence": 0.95,
                "detection_method": "headers",
            }
        ]
        # Without origin_hosts: CDN penalty -8 applies, origin URL
        # is parameterless so composite_score goes <= 0 and gets dropped.
        plain = rank_urls(
            ["https://origin.example.com"],
            base_filters,
            base_scoring_config,
            mode="default",
            waf_findings=waf_findings,
        )
        assert all(item["url"] != "https://origin.example.com" for item in plain)

        # With origin_hosts: penalty suppressed, host survives.
        with_bypass = rank_urls(
            ["https://origin.example.com"],
            base_filters,
            base_scoring_config,
            mode="default",
            waf_findings=waf_findings,
            origin_hosts={"origin.example.com"},
        )
        origin_items = [item for item in with_bypass if item["url"] == "https://origin.example.com"]
        assert len(origin_items) == 1
        assert "cdn_protected" not in origin_items[0]["signals"]
        assert "origin_bypass" in origin_items[0]["signals"]
        # Score is positive (5 bonus offsets the -6 no-params penalty and
        # the +3 correlation boost applies).
        assert origin_items[0]["score"] > 0

    def test_origin_host_survives_strict_tier_filter(self, base_filters, base_scoring_config):
        from src.recon.scoring import rank_urls

        # A parameterless origin URL with no auth/api signals would
        # normally be filtered by the strict tier (no params, signal
        # count < 2, score < 22). The origin_bypass signal must
        # bypass the strict-tier filter.
        result = rank_urls(
            [],
            base_filters,
            base_scoring_config,
            mode="default",
            origin_hosts={"origin.example.com"},
        )
        url_strings = {item["url"] for item in result}
        assert "https://origin.example.com" in url_strings

    def test_existing_url_not_duplicated(self, base_filters, base_scoring_config):
        from src.recon.scoring import rank_urls

        urls = ["https://origin.example.com/api?id=1"]
        result = rank_urls(
            urls,
            base_filters,
            base_scoring_config,
            mode="default",
            origin_hosts={"origin.example.com"},
        )
        # The origin host was already in the input; we should see it
        # once, not twice.
        origin_count = sum(1 for item in result if "origin.example.com" in item["url"])
        assert origin_count == 1

    def test_empty_origin_hosts_is_noop(self, base_filters, base_scoring_config):
        from src.recon.scoring import rank_urls

        urls = ["https://www.example.com/api?id=1"]
        result = rank_urls(
            urls, base_filters, base_scoring_config, mode="default", origin_hosts=None
        )
        url_strings = {item["url"] for item in result}
        assert "https://www.example.com/api?id=1" in url_strings
        # No origin URLs were fabricated.
        for url in url_strings:
            assert "origin" not in url
