"""CLI and dashboard must register the same protocol bindings."""

from __future__ import annotations

from src.bootstrap.startup_registration import register_process_bindings
from src.core.contracts.protocol_registry import (
    get_active_manifest_registry,
    get_launcher_manifest,
    get_oauth_authenticator_cls,
    get_validation_runtime,
)


def _critical_bindings() -> dict[str, object]:
    return {
        "oauth": get_oauth_authenticator_cls(),
        "validation_runtime": get_validation_runtime(),
        "active_manifests": get_active_manifest_registry(),
        "launcher_manifest": get_launcher_manifest(),
    }


def test_register_process_bindings_fills_critical_protocols() -> None:
    register_process_bindings()
    bound = _critical_bindings()
    assert bound["oauth"] is not None
    assert bound["validation_runtime"] is not None
    assert bound["active_manifests"] is not None
    assert bound["launcher_manifest"] is not None
    assert hasattr(bound["launcher_manifest"], "build_launcher_replay_manifest")


def test_cli_runtime_and_dashboard_lifespan_use_the_same_helper() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    runtime_src = (root / "src" / "pipeline" / "runtime.py").read_text(encoding="utf-8")
    lifespan_src = (root / "src" / "dashboard" / "fastapi" / "lifespan.py").read_text(
        encoding="utf-8"
    )
    assert "register_process_bindings" in runtime_src
    assert "register_process_bindings" in lifespan_src
    assert "register_all_implementations()" not in lifespan_src


def test_lifespan_resets_protocol_registry_and_event_bus() -> None:
    from pathlib import Path

    lifespan_src = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "dashboard"
        / "fastapi"
        / "lifespan.py"
    ).read_text(encoding="utf-8")
    assert "reset_startup_registration" in lifespan_src
    assert "reset_event_bus" in lifespan_src


def test_cli_and_dashboard_binding_snapshots_match() -> None:
    register_process_bindings()
    first = _critical_bindings()
    register_process_bindings()
    second = _critical_bindings()
    assert first["oauth"] is second["oauth"]
    assert first["validation_runtime"] is second["validation_runtime"]
    assert first["active_manifests"] is second["active_manifests"]
    assert first["launcher_manifest"] is second["launcher_manifest"]
