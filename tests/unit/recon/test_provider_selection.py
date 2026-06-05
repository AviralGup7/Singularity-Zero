"""Tests for the shared in-house collector provider selection logic."""

from __future__ import annotations

from types import SimpleNamespace

from src.recon.collectors import provider_selection as ps


def _cfg(tools: dict | None = None, **overrides) -> SimpleNamespace:
    """Build a minimal config object with the attributes the provider
    selection logic reads."""
    base = {
        "waybackurls": {"timeout_seconds": 30},
        "commoncrawl": {"timeout_seconds": 30},
        "urlscan": {"timeout_seconds": 30},
        "otx": {"timeout_seconds": 30},
        "katana": {"timeout_seconds": 30, "max_pages_per_host": 12, "workers": 6},
    }
    base.update(overrides)
    return SimpleNamespace(tools=tools or {}, filters={}, **base)


class TestSelectEnabledProviders:
    def test_all_default_providers_present(self) -> None:
        specs = ps.select_enabled_providers(_cfg())
        names = [s.name for s in specs]
        assert "wayback" in names
        assert "commoncrawl" in names
        assert "urlscan" in names
        assert "otx" in names
        assert "crawler" in names

    def test_disabled_tools_excluded(self) -> None:
        cfg = _cfg(
            tools={
                "waybackurls": False,
                "commoncrawl": False,
                "urlscan": False,
                "otx": False,
                "katana": False,
            }
        )
        assert ps.select_enabled_providers(cfg) == []

    def test_only_wayback_enabled(self) -> None:
        cfg = _cfg(
            tools={
                "waybackurls": True,
                "commoncrawl": False,
                "urlscan": False,
                "otx": False,
                "katana": False,
            }
        )
        names = [s.name for s in ps.select_enabled_providers(cfg)]
        assert names == ["wayback"]

    def test_provider_order_is_stable(self) -> None:
        # Order matters because expensive providers (crawler) run last.
        cfg = _cfg()
        names = [s.name for s in ps.select_enabled_providers(cfg)]
        # crawler must always be the last one
        assert names[-1] == "crawler"

    def test_per_host_limit_override(self) -> None:
        cfg = _cfg()
        cfg.filters["per_host_archive_limit"] = 250
        cfg.filters["crawler_max_pages_per_host"] = 99
        cfg.filters["crawler_workers"] = 3
        specs = {s.name: s for s in ps.select_enabled_providers(cfg)}
        assert specs["wayback"].per_host_limit == 250
        assert specs["commoncrawl"].per_host_limit == 250
        assert specs["crawler"].per_host_limit == 99
        assert specs["crawler"].max_workers == 3

    def test_tool_specific_timeout(self) -> None:
        cfg = _cfg()
        cfg.waybackurls["timeout_seconds"] = 999
        cfg.katana["timeout_seconds"] = 5
        specs = {s.name: s for s in ps.select_enabled_providers(cfg)}
        assert specs["wayback"].timeout_seconds == 999
        assert specs["crawler"].timeout_seconds == 5
