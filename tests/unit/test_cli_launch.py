"""Unit tests for the 'cyber launch' CLI command and argument parsing."""

import argparse
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
    @patch("src.cli.commands.start.Path")
    @patch("threading.Thread")
    @patch("src.dashboard.fastapi.main.main")
    def test_handle_launch_execution_flow(
        self,
        mock_run_server: MagicMock,
        mock_thread: MagicMock,
        mock_path: MagicMock,
        mock_console: MagicMock,
    ) -> None:
        """Verify the full orchestration flow of handle_launch."""
        mock_path_instance = MagicMock()
        mock_path.return_value = mock_path_instance
        mock_path_instance.__truediv__.return_value.exists.return_value = True

        args = argparse.Namespace(
            host="127.0.0.1", port=8000, concurrency=2, queue="security-pipeline"
        )

        handle_launch(args)

        import src.cli.commands.start as start_mod

        mock_path.assert_any_call(start_mod.__file__)

        mock_thread.assert_called_once()
        mock_thread.return_value.start.assert_called_once()

        mock_run_server.assert_called_once_with(
            ["--host", "127.0.0.1", "--port", "8000", "--workers", "1"]
        )
