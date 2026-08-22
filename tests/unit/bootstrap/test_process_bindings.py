"""CLI and dashboard must register the same protocol bindings."""

from __future__ import annotations

import inspect

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
    from src.dashboard.fastapi import lifespan as dashboard_lifespan
    from src.pipeline import runtime as pipeline_runtime

    runtime_src = inspect.getsource(pipeline_runtime.main)
    lifespan_src = inspect.getsource(dashboard_lifespan.lifespan)
    assert "register_process_bindings" in runtime_src
    assert "register_process_bindings" in lifespan_src
    assert "register_all_implementations()" not in lifespan_src


def test_cli_and_dashboard_binding_snapshots_match() -> None:
    register_process_bindings()
    first = _critical_bindings()
    register_process_bindings()
    second = _critical_bindings()
    assert first["oauth"] is second["oauth"]
    assert first["validation_runtime"] is second["validation_runtime"]
    assert first["active_manifests"] is second["active_manifests"]
    assert first["launcher_manifest"] is second["launcher_manifest"]
