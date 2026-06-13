import pytest

from src.execution.frontier.wasm import WASMPluginHost


def test_wasm_mock_execution(monkeypatch):
    monkeypatch.setenv("FEATURE_WASM_PLUGINS", "false")
    host = WASMPluginHost("dummy.wasm")
    with pytest.raises(RuntimeError, match="missing required exports"):
        host.run_detector({"test": "data"})


def test_isolated_scanner_validation():
    from src.analysis.plugins.wasm import IsolatedScanner

    scanner = IsolatedScanner(
        plugin_id="test_scanner",
        wasm_path="dummy.wasm",
        allowed_inputs=["target_url", "intensity"],
        expected_outputs=["vulnerabilities", "severity"],
    )

    stage_input = {"target_url": "http://example.com", "intensity": "high", "secret_key": "12345"}
    filtered_input = scanner.validate_input(stage_input)
    assert "secret_key" not in filtered_input
    assert filtered_input["intensity"] == "high"

    raw_output = {"vulnerabilities": ["SQLi"], "severity": "high", "internal_debug": "verbose"}
    filtered_output = scanner.validate_output(raw_output)
    assert "internal_debug" not in filtered_output
    assert filtered_output["severity"] == "high"
