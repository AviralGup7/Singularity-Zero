import pytest

from src.core.frontier.wasm import WASMPluginHost


def test_wasm_mock_execution(monkeypatch):
    monkeypatch.setenv("FEATURE_WASM_PLUGINS", "false")
    host = WASMPluginHost("dummy.wasm")
    with pytest.raises(RuntimeError, match="missing required exports"):
        host.run_detector({"test": "data"})
