from unittest.mock import MagicMock, patch

from src.core.models.config import Config
from src.recon.urls import _normalize_collection_hostnames, collect_urls, extract_parameters_wrapper


class TestUrls:
    def test_normalize_collection_hostnames(self):
        live_hosts = {"https://host1.com", "host2.com:8080"}
        scope_entries = ["*.example.com"]
        hostnames = _normalize_collection_hostnames(live_hosts, scope_entries)
        assert hostnames == ["host1.com", "host2.com"]

        # If live_hosts is empty, use scope
        hostnames = _normalize_collection_hostnames(set(), ["example.com", "test.local"])
        assert hostnames == ["example.com", "test.local"]

    @patch("src.recon.urls.list_plugins")
    @patch("src.recon.urls.run_archive_jobs")
    @patch("src.recon.urls.tool_available")
    def test_collect_urls_basic(self, mock_tool_avail, mock_run_archive, mock_list_plugins):
        mock_tool_avail.return_value = True
        mock_run_archive.return_value = (
            {"https://arch1.com"},
            {"gau": {"status": "ok", "duration_seconds": 1, "new_urls": 1}},
        )

        # Mock plugins
        mock_reg_gau = MagicMock()
        mock_reg_gau.key = "gau"
        mock_reg_gau.metadata = {"type": "archive_command", "args": ["gau"]}

        mock_list_plugins.return_value = [mock_reg_gau]

        config = MagicMock(spec=Config)
        config.tools = {"gau": True, "waybackurls": False, "katana": False}
        config.filters = {"archive_host_threshold": 100}
        config.gau = {"extra_args": []}

        live_hosts = {"https://host1.com"}
        urls = collect_urls(live_hosts, [], config)

        assert "https://arch1.com" in urls
        assert "https://host1.com" in urls  # live hosts added at the end

    @patch("src.recon.urls.extract_parameters")
    def test_extract_parameters_wrapper(self, mock_extract):
        mock_extract.return_value = {"param1"}
        assert extract_parameters_wrapper(["url1"]) == {"param1"}

    @patch("src.recon.urls.list_plugins")
    @patch("src.recon.urls.emit_collection_progress")
    def test_collect_urls_inhouse(self, mock_emit, mock_list_plugins):
        # Mock inhouse collector
        mock_reg_inhouse = MagicMock()
        mock_reg_inhouse.key = "inhouse"
        mock_reg_inhouse.metadata = {"type": "python"}
        mock_reg_inhouse.provider = MagicMock(return_value={"https://inhouse1.com"})

        mock_list_plugins.return_value = [mock_reg_inhouse]

        config = MagicMock(spec=Config)
        config.tools = {"inhouse_collectors": True}
        config.filters = {}

        urls = collect_urls(set(), ["example.com"], config)
        assert "https://inhouse1.com" in urls
        mock_reg_inhouse.provider.assert_called_once()
