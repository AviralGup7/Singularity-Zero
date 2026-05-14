from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.core.plugins.registry import PluginRegistration
from src.recon.collectors import aggregator
from src.recon.urls import collect_urls


def test_collect_urls_uses_inhouse_aggregator():
    config = SimpleNamespace(
        tools={"inhouse_collectors": True},
        filters={"ignore_extensions": []},
        gau={},
        waybackurls={},
        katana={},
    )

    stage_meta: dict[str, object] = {}

    mock_provider = MagicMock(return_value={"https://app.example.com/health"})
    with patch("src.recon.urls.list_plugins") as mock_list_plugins:
        mock_list_plugins.return_value = [
            PluginRegistration(kind="url_collector", key="inhouse", provider=mock_provider, metadata={})
        ]
        urls = collect_urls(
            live_hosts={"https://app.example.com"},
            scope_entries=["app.example.com"],
            config=config,
            stage_meta=stage_meta,
        )

    mock_provider.assert_called()
    assert "https://app.example.com/health" in urls


def test_inhouse_aggregator_normalizes_live_host_inputs() -> None:
    config = SimpleNamespace(
        tools={
            "waybackurls": True,
            "commoncrawl": False,
            "katana": False,
            "urlscan": False,
            "otx": False,
        },
        filters={"ignore_extensions": []},
    )

    captured_hosts: list[str] = []

    def _capture_wayback_hosts(hosts: list[str], *_args: object, **_kwargs: object):
        captured_hosts.extend(list(hosts))
        return set(), {"status": "empty", "duration_seconds": 0.0, "new_urls": 0}

    with patch.object(aggregator.wayback, "collect_for_hosts", side_effect=_capture_wayback_hosts):
        aggregator.collect_urls(
            {
                "https://API.Example.com:443",
                "http://www.example.com/path",
                "example.net",
            },
            ["example.com"],
            config,
            progress_callback=None,
            stage_meta={},
        )

    assert set(captured_hosts) == {"api.example.com", "www.example.com", "example.net"}
    assert all("://" not in host and "/" not in host for host in captured_hosts)
