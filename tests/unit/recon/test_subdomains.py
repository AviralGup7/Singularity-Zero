import json
from unittest.mock import MagicMock, patch

from src.recon.subdomains import enumerate_subdomains, fetch_crtsh_subdomains


class TestSubdomains:
    @patch("requests.get")
    def test_fetch_crtsh_subdomains_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.text = json.dumps(
            [
                {"name_value": "test1.example.com\ntest2.example.com"},
                {"name_value": "*.wildcard.example.com"},
            ]
        )
        mock_get.return_value = mock_resp

        subs = fetch_crtsh_subdomains("example.com", timeout_seconds=5)
        assert "test1.example.com" in subs
        assert "test2.example.com" in subs
        assert "wildcard.example.com" in subs

    @patch("requests.get")
    @patch("src.recon.subdomains.sleep_before_retry")
    def test_fetch_crtsh_subdomains_retry(self, mock_sleep, mock_get):
        import requests

        mock_get.side_effect = [requests.RequestException("fail"), MagicMock(text="[]")]

        retry_policy = MagicMock()
        retry_policy.max_attempts = 2
        retry_policy.delay_for_attempt.return_value = 0.1

        subs = fetch_crtsh_subdomains("example.com", timeout_seconds=5, retry_policy=retry_policy)
        assert subs == set()
        assert mock_get.call_count == 2

    @patch("src.recon.subdomains.list_plugins")
    @patch("src.recon.subdomains.run_commands_parallel")
    @patch("src.recon.subdomains.tool_available")
    def test_enumerate_subdomains(self, mock_tool_avail, mock_run_parallel, mock_list_plugins):
        mock_tool_avail.return_value = True
        mock_run_parallel.return_value = ["sub1.example.com\nsub2.example.com"]

        # Mock crtsh provider
        mock_reg_crtsh = MagicMock()
        mock_reg_crtsh.key = "crtsh"
        mock_reg_crtsh.metadata = {"type": "python"}
        mock_reg_crtsh.provider = MagicMock(return_value={"crtsh1.example.com"})

        # Mock CLI tool provider
        mock_reg_subfinder = MagicMock()
        mock_reg_subfinder.key = "subfinder"
        mock_reg_subfinder.metadata = {"type": "command", "args": ["subfinder", "-d", "{root}"]}

        mock_list_plugins.return_value = [mock_reg_crtsh, mock_reg_subfinder]

        config = {"tools": {"crtsh": True, "subfinder": True}, "http_timeout_seconds": 30}

        subs = enumerate_subdomains(["example.com"], config, skip_crtsh=False)

        assert "crtsh1.example.com" in subs
        assert "sub1.example.com" in subs
        assert "sub2.example.com" in subs
        assert "example.com" in subs  # Root domain always added

    def test_fetch_crtsh_subdomains_boundary_inputs(self):
        # Null bytes
        assert fetch_crtsh_subdomains("example\x00.com", timeout_seconds=5) == set()
        # URL-encoded null bytes
        assert fetch_crtsh_subdomains("example%00.com", timeout_seconds=5) == set()
        # Newlines
        assert fetch_crtsh_subdomains("example\n.com", timeout_seconds=5) == set()
        assert fetch_crtsh_subdomains("example\r.com", timeout_seconds=5) == set()
        # URL-encoded newlines
        assert fetch_crtsh_subdomains("example%0a.com", timeout_seconds=5) == set()
        assert fetch_crtsh_subdomains("example%0d.com", timeout_seconds=5) == set()
        # Other bad characters
        assert fetch_crtsh_subdomains("example/foo.com", timeout_seconds=5) == set()
        assert fetch_crtsh_subdomains("example\\foo.com", timeout_seconds=5) == set()
        assert fetch_crtsh_subdomains("example@foo.com", timeout_seconds=5) == set()
