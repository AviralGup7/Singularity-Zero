"""API-key sidecar must honor the existing _is_enabled gate."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from src.execution.validators.runtime import execute_validation_runtime


def _analysis() -> dict[str, list[dict[str, Any]]]:
    return {
        "ssrf_candidate_finder": [
            {
                "url": "https://app.example.com/fetch?url=http://169.254.169.254",
                "score": 8,
                "signals": ["internal_host_reference:url"],
                "parameters": ["url"],
            }
        ],
        "idor_candidate_finder": [],
        "token_leak_detector": [],
        "behavior_analysis_layer": [],
    }


def _runtime() -> dict[str, Any]:
    return {"urls": ["https://app.example.com/"], "responses": []}


def _run(validation_settings: dict[str, Any] | None = None) -> tuple[Any, Any]:
    mocked_checklist = patch(
        "src.execution.validators.api_keys.run_api_key_checklist",
        return_value={"status": "none", "candidates_tested": 0, "results": []},
    )
    with mocked_checklist as checklist:
        summary = execute_validation_runtime(
            _analysis(),
            [],
            validation_settings,
            runtime_inputs=_runtime(),
        )
    return summary, checklist


def test_implicit_default_still_runs_api_key_plugin() -> None:
    summary, checklist = _run({"blackbox_validation": {"active_probe_enabled": False}})
    checklist.assert_called()
    assert "api_key_validation" in summary["results"]


def test_explicit_ssrf_only_disables_api_key_sidecar() -> None:
    summary, checklist = _run(
        {
            "blackbox_validation": {
                "active_probe_enabled": False,
                "enabled_validators": ["ssrf"],
            }
        }
    )
    checklist.assert_not_called()
    assert summary["results"]["api_key_validation"] == []


def test_explicit_api_key_request_keeps_sidecar_on() -> None:
    summary, checklist = _run(
        {
            "blackbox_validation": {
                "active_probe_enabled": False,
                "enabled_validators": ["api_key"],
            }
        }
    )
    checklist.assert_called()
    assert summary["settings"]["requested_validators"] == ["api_key"]
    assert "api_key_validation" in summary["results"]
