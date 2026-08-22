"""Registration retries missing binds and OAuth cannot fail open."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.bootstrap import startup_registration as boot
from src.bootstrap.startup_registration import binding_status, reset_startup_registration
from src.core.contracts.protocol_registry import get_oauth_authenticator_cls


@pytest.fixture(autouse=True)
def _reset_bindings() -> None:
    reset_startup_registration()
    yield
    reset_startup_registration()


def test_partial_import_failure_does_not_set_registered() -> None:
    original = boot._try_bind

    def _wrap(name: str, loader: object, *, critical: bool = False) -> None:
        if name == "oauth_authenticator_cls":
            original(
                name, lambda: (_ for _ in ()).throw(ImportError("oauth missing")), critical=True
            )
            return
        original(name, loader, critical=critical)

    with patch.object(boot, "_try_bind", side_effect=_wrap):
        boot.register_all_implementations()

    status = binding_status()
    assert "oauth_authenticator_cls" in status["failed"]
    assert "oauth_authenticator_cls" in status["critical_missing"]
    assert boot._REGISTERED is False
    assert get_oauth_authenticator_cls() is None


def test_second_register_retries_failed_critical_bind() -> None:
    original = boot._try_bind
    calls = {"oauth": 0}

    def _wrap(name: str, loader: object, *, critical: bool = False) -> None:
        if name == "oauth_authenticator_cls":
            calls["oauth"] += 1
            if calls["oauth"] == 1:
                original(
                    name,
                    lambda: (_ for _ in ()).throw(ImportError("temp")),
                    critical=True,
                )
                return
        original(name, loader, critical=critical)

    with patch.object(boot, "_try_bind", side_effect=_wrap):
        boot.register_all_implementations()
        assert boot._REGISTERED is False
        boot.register_all_implementations()

    assert get_oauth_authenticator_cls() is not None
    assert binding_status()["critical_missing"] == []


def test_oauth_method_fails_stage_when_unbound() -> None:
    import importlib.util
    from pathlib import Path

    from src.core.contracts.pipeline_runtime import StageOutcome

    path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "pipeline"
        / "services"
        / "pipeline_orchestrator"
        / "stages"
        / "session_provisioning.py"
    )
    spec = importlib.util.spec_from_file_location("session_provisioning_isolated", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SessionProvisioningStage = module.SessionProvisioningStage

    pipeline = SimpleNamespace(
        auth=SimpleNamespace(method="oauth", base_url="https://example.com", username="u"),
        run_id="run-1",
    )
    result = asyncio.run(SessionProvisioningStage.execute(SimpleNamespace(pipeline=pipeline)))
    assert result.outcome is StageOutcome.FAILED
    assert result.reason == "oauth_binding_missing"
    assert "unauthenticated" in (result.error or "").lower()
