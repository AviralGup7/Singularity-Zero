from types import SimpleNamespace
from unittest.mock import patch

from src.core.plugins.registry import PluginRegistration
from src.recon.gau_helpers import resolve_gau_extra_args
from src.recon.js_parsers import (
    _extract_js_candidate_urls,
    _extract_script_urls_from_html,
)
from src.recon.urls import (
    _normalize_collection_hostnames,
    collect_urls,
)


def test_resolve_gau_extra_args_expands_legacy_wayback_only() -> None:
    config = SimpleNamespace(
        gau={"extra_args": ["--providers", "wayback"]},
        filters={},
    )

    args = resolve_gau_extra_args(config)

    assert "--providers" in args
    assert "wayback,commoncrawl,urlscan,otx" in args


def test_resolve_gau_extra_args_respects_disable_flag() -> None:
    config = SimpleNamespace(
        gau={"extra_args": ["--providers", "wayback"]},
        filters={"gau_auto_expand_providers": False},
    )

    args = resolve_gau_extra_args(config)

    assert args == ["--providers", "wayback"]


def test_resolve_gau_extra_args_keeps_custom_provider_set() -> None:
    config = SimpleNamespace(
        gau={"extra_args": ["--providers", "commoncrawl,urlscan"]},
        filters={},
    )

    args = resolve_gau_extra_args(config)

    assert args == ["--providers", "commoncrawl,urlscan"]


def test_extract_js_candidate_urls_resolves_relative_and_scoped_links() -> None:
    content = """
    const a = '/api/v1/users?id=1';
    const b = '../admin/panel';
    const c = './v2/orders';
    const d = 'https://cdn.thirdparty.com/lib.js';
    """

    result = _extract_js_candidate_urls(
        content,
        "https://app.example.com/static/main.js",
        {"example.com"},
    )

    assert "https://app.example.com/api/v1/users?id=1" in result
    assert "https://app.example.com/admin/panel" in result
    assert "https://app.example.com/static/v2/orders" in result
    assert all("thirdparty.com" not in url for url in result)


def test_extract_script_urls_from_html_captures_src_and_dynamic_import() -> None:
    html = """
    <html>
      <head>
        <script src="/assets/app.js"></script>
        <script>import('/chunks/runtime.js')</script>
      </head>
    </html>
    """

    result = _extract_script_urls_from_html(
        html,
        "https://app.example.com/",
        {"example.com"},
    )

    assert "https://app.example.com/assets/app.js" in result
    assert "https://app.example.com/chunks/runtime.js" in result


def test_normalize_collection_hostnames_prefers_live_hosts_and_canonicalizes() -> None:
    hostnames = _normalize_collection_hostnames(
        {
            "https://api.example.com",
            "portal.example.com/path",
            "",
        },
        ["example.com", "https://ignored.scope.example"],
    )

    assert hostnames == ["api.example.com", "portal.example.com"]


def test_collect_urls_includes_js_discovery_source() -> None:
    config = SimpleNamespace(
        tools={"gau": False, "waybackurls": False, "katana": False},
        filters={"ignore_extensions": []},
        gau={"extra_args": [], "timeout_seconds": 1},
        waybackurls={"extra_args": [], "timeout_seconds": 1},
        katana={"extra_args": [], "timeout_seconds": 1},
    )

    stage_meta: dict[str, object] = {}
    js_discovered = {
        "https://app.example.com/api/health",
        "https://app.example.com/v1/users?id=7",
    }

    with patch("src.recon.urls.list_plugins") as mock_list_plugins:
        mock_list_plugins.return_value = [
            PluginRegistration(
                kind="url_collector",
                key="js_discovery",
                provider=lambda *args, **kwargs: (
                    js_discovered,
                    {"status": "ok", "duration_seconds": 0.2, "new_urls": 0},
                ),
                metadata={},
            )
        ]
        urls = collect_urls(
            live_hosts={"https://app.example.com"},
            scope_entries=["app.example.com"],
            config=config,
            stage_meta=stage_meta,
        )

    assert "https://app.example.com/api/health" in urls
    assert "https://app.example.com/v1/users?id=7" in urls
    assert stage_meta["js_discovery"]["status"] == "ok"
    assert stage_meta["js_discovery"]["new_urls"] >= 2
