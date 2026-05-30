from __future__ import annotations

from pathlib import Path

import pytest

from src.core.plugins.loader import DynamicPluginCatalog
from src.core.plugins.sandbox import ProcessSandboxCallable


def test_dynamic_plugin_catalog_loads_and_executes_process_plugin(tmp_path: Path) -> None:
    plugin_file = tmp_path / "demo_check.py"
    plugin_file.write_text(
        """
PLUGIN_MANIFEST = {
    "id": "demo.header_check",
    "name": "Demo Header Check",
    "version": "1.0.0",
    "kind": "validator",
    "description": "Demo validator",
    "group": "exposure",
    "entrypoint": "run",
    "sandbox": "process",
    "timeout_seconds": 5,
}


def run(payload):
    return {"ok": True, "url": payload["target"]["url"]}
""".strip(),
        encoding="utf-8",
    )

    catalog = DynamicPluginCatalog((tmp_path,))
    records = catalog.refresh()

    assert len(records) == 1
    record = records[0]
    assert record.manifest.id == "demo.header_check"
    runner = ProcessSandboxCallable(record.manifest, record.path)
    assert runner({"target": {"url": "https://example.test"}}) == {
        "ok": True,
        "url": "https://example.test",
    }


def test_dynamic_plugin_catalog_reports_invalid_plugins(tmp_path: Path) -> None:
    plugin_file = tmp_path / "bad_check.py"
    plugin_file.write_text(
        """
PLUGIN_MANIFEST = {
    "id": "bad.check",
    "name": "Bad Check",
    "version": "1.0.0",
    "kind": "analysis",
    "description": "Bad plugin",
}

import os


def run(payload):
    return []
""".strip(),
        encoding="utf-8",
    )

    catalog = DynamicPluginCatalog((tmp_path,))

    assert catalog.refresh() == ()
    invalid = catalog.invalid_manifests()
    assert len(invalid) == 1
    assert "Import 'os' is not allowed" in invalid[0].errors[0]


def test_dynamic_plugin_catalog_accepts_sdk_manifest_helper(tmp_path: Path) -> None:
    plugin_file = tmp_path / "helper_check.py"
    plugin_file.write_text(
        """
from src.core.plugins.sdk import manifest

PLUGIN_MANIFEST = manifest(
    id="helper.check",
    name="Helper Check",
    version="1.0.0",
    kind="analysis",
    description="Uses the SDK helper",
)


def run(payload):
    return []
""".strip(),
        encoding="utf-8",
    )

    catalog = DynamicPluginCatalog((tmp_path,))

    records = catalog.refresh()
    assert len(records) == 1
    assert records[0].manifest.name == "Helper Check"


def test_dynamic_plugin_catalog_hot_reload_updates_manifest(tmp_path: Path) -> None:
    plugin_file = tmp_path / "reload_check.py"
    plugin_file.write_text(
        """
PLUGIN_MANIFEST = {
    "id": "reload.check",
    "name": "Reload Check",
    "version": "1.0.0",
    "kind": "analysis",
    "description": "First",
}


def run(payload):
    return []
""".strip(),
        encoding="utf-8",
    )
    catalog = DynamicPluginCatalog((tmp_path,))
    assert catalog.refresh()[0].manifest.description == "First"

    plugin_file.write_text(
        """
PLUGIN_MANIFEST = {
    "id": "reload.check",
    "name": "Reload Check",
    "version": "1.0.1",
    "kind": "analysis",
    "description": "Second",
}


def run(payload):
    return []
""".strip(),
        encoding="utf-8",
    )

    assert catalog.refresh()[0].manifest.description == "Second"


def test_process_sandbox_rejects_non_json_output(tmp_path: Path) -> None:
    plugin_file = tmp_path / "none_check.py"
    plugin_file.write_text(
        """
PLUGIN_MANIFEST = {
    "id": "none.check",
    "name": "None Check",
    "version": "1.0.0",
    "kind": "validator",
    "description": "None plugin",
}


def run(payload):
    print("extra")
    return []
""".strip(),
        encoding="utf-8",
    )
    catalog = DynamicPluginCatalog((tmp_path,))
    record = catalog.refresh()[0]
    runner = ProcessSandboxCallable(record.manifest, record.path)

    with pytest.raises(Exception, match="non-JSON output"):
        runner({})
