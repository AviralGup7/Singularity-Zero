"""Tests for :mod:`src.recon.collectors.health` (ProviderHealthRegistry)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from src.recon.collectors.health import (
    DEFAULT_COOL_DOWN_SECONDS,
    DEFAULT_FAILURE_THRESHOLD,
    HEALTH_REGISTRY,
    ProviderHealth,
    ProviderHealthRegistry,
    is_circuit_open,
    new_registry_for_tests,
    record_failure,
    record_success,
    reset_health_state,
)


class TestProviderHealth:
    def test_circuit_closed_by_default(self) -> None:
        h = ProviderHealth()
        assert h.is_circuit_open(cool_down_seconds=DEFAULT_COOL_DOWN_SECONDS) is False

    def test_circuit_open_within_cooldown(self) -> None:
        h = ProviderHealth(circuit_opened_at=time.time() - 5)
        assert h.is_circuit_open(cool_down_seconds=60) is True

    def test_circuit_closed_after_cooldown(self) -> None:
        h = ProviderHealth(circuit_opened_at=time.time() - 3600)
        assert h.is_circuit_open(cool_down_seconds=60) is False


class TestRegistryBasics:
    def test_circuit_closed_for_unknown_provider(self) -> None:
        reg = new_registry_for_tests()
        assert reg.is_circuit_open("never-seen") is False

    def test_record_success_resets_failures(self) -> None:
        reg = new_registry_for_tests()
        reg.record_failure("a")
        reg.record_failure("a")
        reg.record_success("a")
        assert reg.snapshot()["a"]["consecutive_failures"] == 0

    def test_record_failure_increments(self) -> None:
        reg = new_registry_for_tests()
        reg.record_failure("a")
        reg.record_failure("a")
        snap = reg.snapshot()["a"]
        assert snap["consecutive_failures"] == 2
        assert snap["total_failures"] == 2

    def test_circuit_opens_at_threshold(self) -> None:
        reg = ProviderHealthRegistry(failure_threshold=3, cool_down_seconds=600)
        for _ in range(2):
            tripped = reg.record_failure("a")
            assert tripped is False
        tripped = reg.record_failure("a")
        assert tripped is True
        assert reg.is_circuit_open("a") is True

    def test_circuit_stays_open_through_failures(self) -> None:
        reg = ProviderHealthRegistry(failure_threshold=2, cool_down_seconds=600)
        reg.record_failure("a")
        reg.record_failure("a")
        # Further failures don't re-trip (already open).
        second_trip = reg.record_failure("a")
        assert second_trip is False
        assert reg.is_circuit_open("a") is True

    def test_circuit_resets_on_success(self) -> None:
        reg = ProviderHealthRegistry(failure_threshold=2, cool_down_seconds=600)
        reg.record_failure("a")
        reg.record_failure("a")
        assert reg.is_circuit_open("a") is True
        reg.record_success("a")
        assert reg.is_circuit_open("a") is False
        assert reg.snapshot()["a"]["consecutive_failures"] == 0

    def test_cool_down_remaining(self) -> None:
        reg = ProviderHealthRegistry(cool_down_seconds=100)
        reg.record_failure("a", error="boom")
        reg.record_failure("a", error="boom")
        reg.record_failure("a", error="boom")
        remaining = reg.cool_down_remaining("a")
        assert 0 < remaining <= 100

    def test_cool_down_remaining_unknown_provider(self) -> None:
        reg = new_registry_for_tests()
        assert reg.cool_down_remaining("never-seen") == 0.0

    def test_ema_duration_updates(self) -> None:
        reg = new_registry_for_tests()
        reg.record_success("a", duration_seconds=10.0)
        ema1 = reg.snapshot()["a"]["ema_duration_seconds"]
        reg.record_success("a", duration_seconds=20.0)
        ema2 = reg.snapshot()["a"]["ema_duration_seconds"]
        # EMA should move towards 20 but not jump straight to it.
        assert ema1 == pytest.approx(10.0)
        assert ema2 > ema1
        assert ema2 < 20.0

    def test_reset_clears_all(self) -> None:
        reg = new_registry_for_tests()
        reg.record_failure("a")
        reg.record_failure("b")
        reg.reset()
        assert reg.snapshot() == {}

    def test_reset_clears_one(self) -> None:
        reg = new_registry_for_tests()
        reg.record_failure("a")
        reg.record_failure("b")
        reg.reset("a")
        snap = reg.snapshot()
        assert "a" not in snap
        assert "b" in snap

    def test_known_providers(self) -> None:
        reg = new_registry_for_tests()
        reg.record_failure("a")
        reg.record_failure("b")
        reg.record_success("c")
        assert set(reg.known_providers()) == {"a", "b", "c"}


class TestRegistryPersistence:
    def test_persists_and_reloads(self, tmp_path: Path) -> None:
        path = tmp_path / "health.json"
        reg = ProviderHealthRegistry(state_path=path, failure_threshold=2)
        reg.record_failure("provider-x")
        reg.record_failure("provider-x")
        assert path.exists()

        # A second registry loading the same file should see the open circuit.
        reg2 = ProviderHealthRegistry(state_path=path, failure_threshold=2, cool_down_seconds=600)
        assert reg2.is_circuit_open("provider-x") is True

    def test_ignores_corrupt_state(self, tmp_path: Path) -> None:
        path = tmp_path / "health.json"
        path.write_text("not json {", encoding="utf-8")
        reg = ProviderHealthRegistry(state_path=path)
        # Should not raise; the registry is empty.
        assert reg.snapshot() == {}


class TestModuleLevelHelpers:
    def setup_method(self) -> None:
        reset_health_state()

    def teardown_method(self) -> None:
        reset_health_state()

    def test_is_circuit_open_helper(self) -> None:
        assert is_circuit_open("unknown") is False
        record_failure("a")
        record_failure("a")
        record_failure("a")
        # Default threshold is 3.
        assert is_circuit_open("a") is True

    def test_record_success_helper(self) -> None:
        record_success("a", duration_seconds=2.0)
        snap = HEALTH_REGISTRY.snapshot()
        assert "a" in snap
        assert snap["a"]["total_successes"] == 1

    def test_reset_health_state(self) -> None:
        record_failure("a")
        assert HEALTH_REGISTRY.snapshot() != {}
        reset_health_state()
        assert HEALTH_REGISTRY.snapshot() == {}

    def test_default_constants(self) -> None:
        assert DEFAULT_FAILURE_THRESHOLD >= 1
        assert DEFAULT_COOL_DOWN_SECONDS > 0
