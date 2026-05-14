"""Backward-compatible dashboard handler helpers used by legacy tests.

This lightweight compatibility class preserves form/json normalization
behavior that older tests relied on.
"""

from __future__ import annotations

from typing import Any, cast


class DashboardHandler:
    """Compatibility shim for legacy dashboard handler helpers."""

    def _json_to_params(self, payload: dict[str, Any]) -> dict[str, list[str]]:
        params: dict[str, list[str]] = {}
        for key, value in payload.items():
            if key.endswith("_present"):
                continue
            if key == "modules":
                if isinstance(value, list):
                    module_items = cast(list[Any], value)
                    params[key] = [str(item) for item in module_items]
                elif value is None:
                    params[key] = []
                else:
                    params[key] = [str(value)]
                continue
            if isinstance(value, bool):
                params[key] = ["1" if value else "0"]
                continue
            if value is None:
                continue
            params[key] = [str(value)]
        return params

    def _extract_form_values(self, params: dict[str, list[str]]) -> dict[str, str]:
        values: dict[str, str] = {}
        for key, value in params.items():
            if key == "modules":
                values[key] = ",".join(value)
                continue
            values[key] = value[0] if value else ""
        return values

    def _extract_execution_options(self, params: dict[str, list[str]]) -> dict[str, bool]:
        def _truthy(name: str) -> bool:
            raw = (params.get(name) or ["0"])[0].strip().lower()
            return raw in {"1", "true", "yes", "on"}

        return {
            "refresh_cache": _truthy("refresh_cache"),
            "skip_crtsh": _truthy("skip_crtsh"),
            "dry_run": _truthy("dry_run"),
        }
