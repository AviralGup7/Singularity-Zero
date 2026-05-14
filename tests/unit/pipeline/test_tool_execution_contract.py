"""Contract test: ToolInvocation / CompletedToolRun contract for external tool execution.

All external binary execution MUST go through run_external_tool().
This ensures consistent timeout handling, stderr classification, and
structured results across all tool adapters.

Run with: pytest tests/unit/pipeline/test_tool_execution_contract.py -q
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from src.pipeline.services.tool_execution import (
    CompletedToolRun,
    ToolInvocation,
    run_external_tool,
)


@pytest.mark.unit
class TestToolInvocation:
    """Verify ToolInvocation model."""

    def test_tool_invocation_command_property(self) -> None:
        inv = ToolInvocation(tool_name="nuclei", args=["-list", "targets.txt"])
        assert inv.command == ["nuclei", "-list", "targets.txt"]

    def test_tool_invocation_defaults(self) -> None:
        inv = ToolInvocation(tool_name="subfinder")
        assert inv.args == []
        assert inv.timeout_seconds is None
        assert inv.env is None
        assert inv.working_dir is None
        assert inv.stdin is None
        assert inv.command == ["subfinder"]

    def test_tool_invocation_full(self) -> None:
        inv = ToolInvocation(
            tool_name="ffuf",
            args=["-w", "wordlist.txt", "-u", "https://example.com/FUZZ"],
            timeout_seconds=120,
            env={"GOFLAGS": "-insecure"},
            working_dir="/tmp/scan",
            stdin=None,
        )
        assert inv.tool_name == "ffuf"
        assert inv.timeout_seconds == 120


@pytest.mark.unit
class TestCompletedToolRun:
    """Verify CompletedToolRun model."""

    def test_completed_tool_run_defaults(self) -> None:
        run = CompletedToolRun()
        assert run.stdout == ""
        assert run.stderr == ""
        assert run.exit_code == 0
        assert run.timed_out is False
        assert run.timeout_events == []
        assert run.stderr_classification is None
        assert run.duration_seconds == 0.0

    def test_completed_tool_run_ok_property_success(self) -> None:
        run = CompletedToolRun(exit_code=0, timed_out=False)
        assert run.ok is True

    def test_completed_tool_run_ok_property_nonzero_exit(self) -> None:
        run = CompletedToolRun(exit_code=1, timed_out=False)
        assert run.ok is False

    def test_completed_tool_run_ok_property_timeout(self) -> None:
        run = CompletedToolRun(exit_code=-1, timed_out=True)
        assert run.ok is False

    def test_completed_tool_run_with_stderr_classification(self) -> None:
        from src.core.utils.stderr_classification import StderrClassification

        classification = StderrClassification(
            warnings=["[WARNING] slow response"],
            fatal_signal_lines=["error: template not found"],
        )
        run = CompletedToolRun(
            stdout="scan complete",
            stderr="error: template not found\n[WARNING] slow response",
            exit_code=1,
            timed_out=False,
            timeout_events=[],
            stderr_classification=classification,
            duration_seconds=1.5,
            tool_name="nuclei",
        )
        assert run.ok is False
        assert run.stderr_classification is not None
        assert run.stderr_classification.fatal_signal_count == 1
        assert run.stderr_classification.warning_count == 1


@pytest.mark.unit
class TestRunExternalTool:
    """Verify run_external_tool() is the single entry point for external binaries."""

    @pytest.mark.asyncio
    async def test_run_external_tool_returns_completed_tool_run(self) -> None:
        """run_external_tool must return CompletedToolRun, never raise on timeout."""
        inv = ToolInvocation(tool_name="echo", args=["hello"])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "hello"
            mock_run.return_value.stderr = ""

            result = await run_external_tool(inv)

        assert isinstance(result, CompletedToolRun)
        assert result.ok is True
        assert result.stdout == "hello"
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.timed_out is False
        assert result.tool_name == "echo"

    @pytest.mark.asyncio
    async def test_run_external_tool_timeout_returns_timed_out(self) -> None:
        """Timeout must return timed_out=True, not raise."""
        import subprocess

        inv = ToolInvocation(tool_name="sleep", args=["9999"], timeout_seconds=1)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["sleep", "9999"], timeout=1)

            result = await run_external_tool(inv)

        assert isinstance(result, CompletedToolRun)
        assert result.timed_out is True
        assert result.exit_code == -1
        assert result.timeout_events is not None
        assert result.tool_name == "sleep"

    @pytest.mark.asyncio
    async def test_run_external_tool_nonzero_exit_code(self) -> None:
        """Non-zero exit code must be reflected in result, not raised."""
        inv = ToolInvocation(tool_name="ls", args=["/nonexistent"])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 2
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = "ls: /nonexistent: No such file or directory"

            result = await run_external_tool(inv)

        assert isinstance(result, CompletedToolRun)
        assert result.ok is False
        assert result.exit_code == 2
        assert "No such file" in result.stderr

    @pytest.mark.asyncio
    async def test_run_external_tool_classifies_stderr(self) -> None:
        """Stderr must be classified using classify_stderr_lines."""
        inv = ToolInvocation(tool_name="nuclei", args=["-list", "missing.txt"])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = (
                "Warning: nuclei failed to load some templates\n"
                "error: template file not found\n"
                "[INF] scan complete"
            )

            result = await run_external_tool(inv)

        assert result.stderr_classification is not None
        assert result.stderr_classification.fatal_signal_count >= 1, (
            f"Expected fatal signals, got: {result.stderr_classification.fatal_signal_lines}"
        )
        assert result.stderr_classification.warning_count >= 1, (
            f"Expected warnings, got: {result.stderr_classification.warnings}"
        )

    @pytest.mark.asyncio
    async def test_run_external_tool_respects_env_and_cwd(self) -> None:
        """Environment and working directory must be passed to subprocess."""
        inv = ToolInvocation(
            tool_name="nuclei",
            args=["-list", "targets.txt"],
            env={"NUCLEI_AUTH": "secret"},
            working_dir="/tmp/scan",
        )

        captured_call_kwargs: dict[str, Any] = {}

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""

            def capture_run(*args: Any, **kwargs: Any) -> Any:
                captured_call_kwargs.update(kwargs)
                mock_result = type(
                    "MockResult",
                    (),
                    {
                        "returncode": 0,
                        "stdout": "",
                        "stderr": "",
                    },
                )()
                return mock_result

            mock_run.side_effect = capture_run
            await run_external_tool(inv)

        assert "env" in captured_call_kwargs, (
            f"Expected 'env' in kwargs, got: {captured_call_kwargs}"
        )
        assert captured_call_kwargs["env"]["NUCLEI_AUTH"] == "secret"
        assert captured_call_kwargs["cwd"] == "/tmp/scan"

    @pytest.mark.asyncio
    async def test_run_external_tool_has_duration(self) -> None:
        """Result must include duration_seconds."""
        inv = ToolInvocation(tool_name="echo", args=["test"])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "test"
            mock_run.return_value.stderr = ""

            result = await run_external_tool(inv)

        assert result.duration_seconds >= 0


@pytest.mark.unit
class TestNoDirectSubprocessCalls:
    """Verify no direct subprocess calls in tool adapter modules.

    All external binary execution must go through run_external_tool().
    This test scans for patterns that would bypass the contract.
    """

    def test_tool_execution_module_uses_run_external_tool(self) -> None:
        """The tool_execution module itself uses subprocess.run internally,
        but exposes only run_external_tool() as the public API.
        Other modules must use run_external_tool()."""
        import ast
        from pathlib import Path

        src_root = Path(__file__).resolve().parents[4] / "src"

        VIOLATION_PATTERNS = [
            "subprocess.run",
            "subprocess.Popen",
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
        ]

        violations: list[str] = []

        TOOL_ADAPTER_FILES = [
            "src/recon/subdomains.py",
            "src/recon/urls.py",
            "src/recon/katana.py",
            "src/pipeline/services/pipeline_orchestrator/stages/nuclei.py",
        ]

        for rel_path in TOOL_ADAPTER_FILES:
            filepath = src_root / rel_path
            if not filepath.exists():
                continue
            try:
                content = filepath.read_text(encoding="utf-8")
                tree = ast.parse(content, filename=str(filepath))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute):
                        name = f"{func.value.id if isinstance(func.value, ast.Name) else '?'}.{func.attr}"
                    elif isinstance(func, ast.Name):
                        name = func.id
                    else:
                        name = "?"

                    for pattern in VIOLATION_PATTERNS:
                        if pattern in name:
                            violations.append(f"  {rel_path}:{node.lineno} — direct {pattern}")

        assert violations == [], (
            "Tool adapters must not call subprocess directly. "
            "Use run_external_tool(ToolInvocation(...)) instead.\n" + "\n".join(violations)
        )


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
