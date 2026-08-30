"""Architecture review Phase-4 residual tests."""

from __future__ import annotations

import pytest


def test_observability_dual_env_refuse(monkeypatch):
    from src.infrastructure.observability.config import (
        ObservabilityConfig,
        refuse_conflicting_observability_env,
    )

    monkeypatch.delenv("OBSERVABILITY_METRICS_PORT", raising=False)
    monkeypatch.delenv("PROMETHEUS_PORT", raising=False)
    refuse_conflicting_observability_env()  # no-op

    monkeypatch.setenv("OBSERVABILITY_METRICS_PORT", "9090")
    monkeypatch.setenv("PROMETHEUS_PORT", "9090")
    refuse_conflicting_observability_env()  # agree OK

    monkeypatch.setenv("PROMETHEUS_PORT", "9100")
    with pytest.raises(RuntimeError, match="dual-env conflict"):
        refuse_conflicting_observability_env()

    with pytest.raises(RuntimeError, match="dual-env conflict"):
        ObservabilityConfig.from_env()


def test_stage_admit_exports_scope_release():
    from src.pipeline.services.pipeline_orchestrator import stage_admit as sa

    assert hasattr(sa, "release_stage_scope_lock")
    assert "ScopeGroupLock" in open(sa.__file__, encoding="utf-8").read()
