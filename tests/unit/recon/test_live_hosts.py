import pytest
from unittest.mock import MagicMock, patch
from src.recon.live_hosts import (
    _normalized_probe_hosts,
    _host_from_url,
    _cache_lookup,
    _cache_update,
    probe_host_without_httpx,
    probe_live_hosts,
    probe_live_hosts_fallback,
    clear_probe_cache
)
from src.core.models.config import Config

class TestLiveHosts:
    def setup_method(self):
        clear_probe_cache()

    def test_normalized_probe_hosts(self):
        subdomains = {"EXAMPLE.COM", "  test.local  ", "", None}
        normalized = _normalized_probe_hosts(subdomains)
        assert normalized == ["example.com", "test.local"]

    def test_host_from_url(self):
        assert _host_from_url("https://example.com/path") == "example.com"
        assert _host_from_url("http://localhost:8080") == "localhost:8080"
        assert _host_from_url("invalid") == ""

    def test_cache_logic(self):
        hosts = ["host1.com", "host2.com"]
        _cache_update("host1.com", alive=True, url="https://host1.com", status_code=200)
        
        to_probe, records, live_hosts, skipped = _cache_lookup(hosts, ttl_seconds=600, force_recheck=False)
        
        assert to_probe == ["host2.com"]
        assert len(records) == 1
        assert records[0]["url"] == "https://host1.com"
        assert "https://host1.com" in live_hosts
        assert skipped == 1

    @patch("src.recon.live_hosts.get_pooled_connection")
    def test_probe_host_without_httpx_success(self, mock_get_pool):
        mock_pool = MagicMock()
        mock_get_pool.return_value = mock_pool
        
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.geturl.return_value = "https://example.com"
        mock_pool.request.return_value = mock_resp
        
        result = probe_host_without_httpx("example.com", timeout_seconds=5)
        assert result["url"] == "https://example.com"
        assert result["status_code"] == 200

    @patch("src.recon.live_hosts.get_pooled_connection")
    def test_probe_host_without_httpx_failure(self, mock_get_pool):
        mock_pool = MagicMock()
        mock_get_pool.return_value = mock_pool
        
        import urllib3
        mock_pool.request.side_effect = urllib3.exceptions.HTTPError("fail")
        
        result = probe_host_without_httpx("example.com", timeout_seconds=5)
        assert result is None

    @patch("src.recon.live_hosts.projectdiscovery_httpx_available")
    @patch("src.recon.live_hosts.execute_command")
    def test_probe_live_hosts_httpx(self, mock_execute, mock_httpx_avail):
        mock_httpx_avail.return_value = True
        config = MagicMock(spec=Config)
        config.tools = {"httpx": True}
        config.httpx = {"threads": 80, "extra_args": [], "batch_size": 100}
        config.mode = "full"
        config.http_timeout_seconds = 10
        
        mock_outcome = MagicMock()
        mock_outcome.stdout = '{"url": "https://host1.com", "status_code": 200}\n'
        mock_outcome.timed_out = False
        mock_outcome.fatal = False
        mock_outcome.attempt_count = 1
        mock_outcome.warning_messages = []
        mock_outcome.error_message = None
        mock_outcome.configured_timeout_seconds = 60
        mock_outcome.effective_timeout_seconds = 60
        mock_execute.return_value = mock_outcome
        
        subdomains = {"host1.com"}
        records, live_hosts = probe_live_hosts(subdomains, config)
        
        assert len(records) == 1
        assert "https://host1.com" in live_hosts

    def test_probe_live_hosts_fallback(self):
        config = MagicMock(spec=Config)
        config.mode = "safe"
        config.httpx = {}
        config.http_timeout_seconds = 10
        
        with patch("src.recon.live_hosts.probe_host_without_httpx") as mock_probe:
            mock_probe.return_value = {"url": "https://host1.com", "status_code": 200}
            
            subdomains = {"host1.com"}
            records, live_hosts = probe_live_hosts(subdomains, config)
            
            assert len(records) == 1
            assert "https://host1.com" in live_hosts
