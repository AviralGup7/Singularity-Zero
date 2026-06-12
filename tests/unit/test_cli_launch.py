"""Unit tests for the 'cyber launch' CLI command and argument parsing."""

import argparse
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

from src.cli import _build_parser, handle_launch


@pytest.mark.unit
class TestCliLaunch(unittest.TestCase):
    def test_parser_registers_launch_command(self) -> None:
        """Verify that 'launch' subparser is registered with correct options and defaults."""
        parser = _build_parser()

        args = parser.parse_args(["launch"])
        assert args.area == "launch"
        assert args.host == "127.0.0.1"
        assert args.port == 8000
        assert args.concurrency == 2
        assert args.queue == "security-pipeline"

        args = parser.parse_args(
            [
                "launch",
                "--host",
                "0.0.0.0",
                "--port",
                "9000",
                "--concurrency",
                "4",
                "--queue",
                "custom-queue",
            ]
        )
        assert args.host == "0.0.0.0"
        assert args.port == 9000
        assert args.concurrency == 4
        assert args.queue == "custom-queue"

    @patch("src.cli.ui.console")
    @patch("src.cli.commands.start._ensure_frontend_built", return_value=True)
    @patch("threading.Thread")
    @patch("src.dashboard.fastapi.main.main")
    def test_handle_launch_execution_flow(
        self,
        mock_run_server: MagicMock,
        mock_thread: MagicMock,
        mock_frontend: MagicMock,
        mock_console: MagicMock,
    ) -> None:
        """Verify the full orchestration flow of handle_launch."""
        args = argparse.Namespace(
            host="127.0.0.1", port=8000, concurrency=2, queue="security-pipeline"
        )

        handle_launch(args)

        mock_frontend.assert_called_once()

        mock_thread.assert_called_once()
        mock_thread.return_value.start.assert_called_once()

        mock_run_server.assert_called_once_with(
            ["--host", "127.0.0.1", "--port", "8000", "--workers", "1"]
        )


@pytest.mark.unit
class TestCliSmoke:
    """Smoke tests that invoke the real CLI entry point."""

    def test_main_returns_int(self) -> None:
        """Verify that main() returns an integer exit code."""
        from src.cli import main

        with patch("sys.argv", ["cstp"]):
            result = main()
            assert isinstance(result, int)

    def test_main_no_args_prints_help(self) -> None:
        """Verify that main() with no args returns 0 (help display)."""
        from src.cli import main

        with patch("sys.argv", ["cstp"]):
            result = main()
            assert result == 0

    def test_main_help_flag(self) -> None:
        """Verify that --help exits with code 0."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from src.cli import main; import sys; sys.argv=['cstp','--help']; main()",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        assert "usage:" in combined.lower()

    def test_main_scan_run_requires_config(self) -> None:
        """Verify that 'scan run' without --config exits with error."""
        from src.cli import main

        with patch("sys.argv", ["cstp", "scan", "run"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0

    def test_parser_all_subcommands_registered(self) -> None:
        """Verify all expected subcommands are registered."""
        import io

        parser = _build_parser()
        # Verify 'launch' (no extra required args)
        args = parser.parse_args(["launch"])
        assert args.area == "launch"
        # Verify all expected commands appear in help
        help_buf = io.StringIO()
        parser.print_help(help_buf)
        help_text = help_buf.getvalue().lower()
        for cmd in ["launch", "scan", "start", "system", "plugin"]:
            assert cmd in help_text, f"'{cmd}' not found in help output"
