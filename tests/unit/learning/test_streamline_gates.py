"""Streamline gates: tuner opt-in and fail-open telemetry."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from src.learning.config.learning_config import LearningConfig, ThresholdTuningConfig
from src.learning.integration import LearningIntegration
from src.learning.repositories.telemetry_store import TelemetryStore


def test_threshold_tuning_disabled_by_default() -> None:
    assert ThresholdTuningConfig().enabled is False
    assert LearningConfig().threshold_tuning.enabled is False


def test_threshold_tuning_env_opt_in(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ENABLE_THRESHOLD_TUNING", "true")
    LearningIntegration.reset()
    integration = LearningIntegration.get_or_create(
        config=LearningConfig(database_path=str(tmp_path / "t.db"))
    )
    try:
        assert integration.threshold_tuning_enabled is True
    finally:
        LearningIntegration.reset()


def test_threshold_tuning_env_opt_out_overrides_config(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ENABLE_THRESHOLD_TUNING", "false")
    LearningIntegration.reset()
    cfg = LearningConfig(database_path=str(tmp_path / "t.db"))
    cfg.threshold_tuning.enabled = True
    integration = LearningIntegration.get_or_create(config=cfg)
    try:
        assert integration.threshold_tuning_enabled is False
    finally:
        LearningIntegration.reset()


def test_telemetry_initialize_fail_open(tmp_path: Path, monkeypatch) -> None:
    store = TelemetryStore(tmp_path / "t.db")

    def boom() -> sqlite3.Connection:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "_get_conn", boom)
    store.initialize()
    assert store._initialized is True


def test_telemetry_write_fail_open(tmp_path: Path, monkeypatch) -> None:
    store = TelemetryStore(tmp_path / "t.db")
    store.initialize()

    def boom() -> sqlite3.Connection:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "_get_conn", boom)
    assert store.execute_write("SELECT 1") == 0
