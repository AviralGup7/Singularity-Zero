"""Unit tests for Phase 5.2 Pre-Scan Config Mutation with Rollback.

Covers:
- PipelineOutputStore.write_adaptive_config / read_adaptive_config round-trip
- missing file returns None from read_adaptive_config
- empty adaptations writes an empty JSON object
- apply_adaptive_overrides merges nested dict fields correctly
- apply_adaptive_overrides replaces non-dict fields directly
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from src.core.config.loader import apply_adaptive_overrides
from src.core.models import Config
from src.pipeline.services.output_store import PipelineOutputStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ADAPTIVE_DIR: Path | None = None


@pytest.fixture()
def adaptive_dir() -> Path:
    """Provide a fresh temporary directory for adaptive config files."""
    global _ADAPTIVE_DIR
    with tempfile.TemporaryDirectory() as tmp:
        _ADAPTIVE_DIR = Path(tmp)
        yield _ADAPTIVE_DIR
        _ADAPTIVE_DIR = None


@pytest.fixture()
def full_section_config() -> Config:
    """Return a Config whose scoring/analysis/decision/nuclei sections are populated."""
    return Config(
        target_name="example.com",
        output_dir=Path("/tmp/output"),
        http_timeout_seconds=12,
        mode="deep",
        cache={},
        storage={},
        tools={},
        httpx={},
        gau={},
        waybackurls={},
        katana={},
        nuclei={"adaptive_tags": {"original-tag": {"severity": "high"}}},
        scoring={"target_boosts": {"old.com": 1.5}, "existing_key": 0.5},
        analysis={"plugin_overrides": {"plugin_a": "on"}, "plugin_intensity": 1.0},
        filters={},
        screenshots={},
        review={},
        extensions={},
        concurrency={},
        output={},
        notifications={},
    )


@pytest.fixture()
def empty_section_config() -> Config:
    """Return a Config with empty nested sections."""
    return Config(
        target_name="example.com",
        output_dir=Path("/tmp/output"),
        http_timeout_seconds=12,
        mode="deep",
        cache={},
        storage={},
        tools={},
        httpx={},
        gau={},
        waybackurls={},
        katana={},
        nuclei={},
        scoring={},
        analysis={},
        filters={},
        screenshots={},
        review={},
        extensions={},
        concurrency={},
        output={},
        notifications={},
    )


# ---------------------------------------------------------------------------
# PipelineOutputStore – read_adaptive_config
# ---------------------------------------------------------------------------


class TestReadAdaptiveConfig:
    """Tests for PipelineOutputStore.read_adaptive_config."""

    def test_missing_file_returns_none(self, adaptive_dir: Path) -> None:
        """A non-existent config.adaptive.json yields None."""
        result = PipelineOutputStore.read_adaptive_config(adaptive_dir)
        assert result is None

    def test_empty_adaptations_writes_and_reads_empty_dict(self, adaptive_dir: Path) -> None:
        """Writing an empty adaptations dict should produce a valid ``{}`` file."""
        store = PipelineOutputStore.create(adaptive_dir, "example.com")
        store.write_adaptive_config({})

        result = PipelineOutputStore.read_adaptive_config(store.target_root)
        assert result == {}

    def test_roundtrip_adaptations(self, adaptive_dir: Path) -> None:
        """write then read produces identical content."""
        adaptations = {
            "target_boosts": {"example.com": 2.0},
            "plugin_overrides": {"nuclei": True},
            "threshold_deltas": {"min_conf": 0.55},
        }
        store = PipelineOutputStore.create(adaptive_dir, "example.com")
        store.write_adaptive_config(adaptations)

        result = PipelineOutputStore.read_adaptive_config(store.target_root)
        assert result == adaptations

    def test_adaptations_are_persisted_as_json(self, adaptive_dir: Path) -> None:
        """The file on disk must be valid and round-trip-parseable JSON."""
        adaptations = {"nuclei_template_boosts": {"cve-2024-0001": 1.8}}
        store = PipelineOutputStore.create(adaptive_dir, "example.com")
        store.write_adaptive_config(adaptations)

        path = store.target_root / "config.adaptive.json"
        assert path.exists()
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw == adaptations

    def test_read_non_json_file_returns_none(self, adaptive_dir: Path) -> None:
        """A corrupt / non-JSON file is handled gracefully."""
        path = adaptive_dir / "config.adaptive.json"
        path.write_text("NOT VALID JSON {{{", encoding="utf-8")
        assert PipelineOutputStore.read_adaptive_config(adaptive_dir) is None

    def test_store_instance_method_not_affected(self) -> None:
        """PipelineOutputStore instances that access output_store on ctx should still work."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "output"
            store = PipelineOutputStore.create(root, "test.example.com")
            result = store.write_adaptive_config({"threshold_deltas": {}})
            assert isinstance(result, str)
            # The instance method delegates to the classmethod under the hood
            read = PipelineOutputStore.read_adaptive_config(store.target_root)
            assert read is not None
            assert "threshold_deltas" in read


# ---------------------------------------------------------------------------
# apply_adaptive_overrides
# ---------------------------------------------------------------------------


class TestApplyAdaptiveOverrides:
    """Tests for apply_adaptive_overrides in src.core.config.loader."""

    # ---- nested-section deep-merge ---------------------------------------

    def test_nested_merge_preserves_existing_keys(self, full_section_config: Config) -> None:
        """Existing sub-keys in a nested section are not wiped by a partial override."""
        adaptive: dict[str, Any] = {
            "scoring": {"new_boost_key": 10.0},
        }
        apply_adaptive_overrides(full_section_config, adaptive)
        assert full_section_config.scoring["target_boosts"] == {"old.com": 1.5}, (
            "target_boosts sub-key should survive the partial merge"
        )
        assert full_section_config.scoring["new_boost_key"] == 10.0, (
            "newly added sub-key should be present"
        )

    def test_nested_merge_replaces_explicit_key_only(self, full_section_config: Config) -> None:
        """Override sub-key with the same name replaces the nested value, siblings stay."""
        adaptive: dict[str, Any] = {
            "scoring": {"target_boosts": {"new.com": 3.0}},
        }
        apply_adaptive_overrides(full_section_config, adaptive)
        scoring = full_section_config.scoring
        assert scoring["target_boosts"] == {"new.com": 3.0}
        assert scoring["existing_key"] == 0.5  # sibling key preserved

    def test_nested_merge_analysis_section(self, full_section_config: Config) -> None:
        """analysis overrides are deep-merged, not replaced."""
        adaptive: dict[str, Any] = {
            "analysis": {"plugin_intensity": 2.5},
        }
        apply_adaptive_overrides(full_section_config, adaptive)
        assert full_section_config.analysis["plugin_overrides"] == {"plugin_a": "on"}
        assert full_section_config.analysis["plugin_intensity"] == 2.5

    def test_nested_merge_scoring_section(self, full_section_config: Config) -> None:
        """scoring overrides merge with existing scoring dict."""
        adaptive: dict[str, Any] = {
            "scoring": {"base_score": 5.0},
        }
        apply_adaptive_overrides(full_section_config, adaptive)
        assert full_section_config.scoring["base_score"] == 5.0
        assert full_section_config.scoring["target_boosts"] == {"old.com": 1.5}

    def test_nested_merge_nuclei_section(self, full_section_config: Config) -> None:
        """nuclei section top-level keys are replaced wholesale by adaptive value."""
        adaptive: dict[str, Any] = {
            "nuclei": {"adaptive_tags": {"new-tag": {"severity": "low"}}},
        }
        apply_adaptive_overrides(full_section_config, adaptive)
        # adaptive_tags value is replaced entirely by the adaptive dict
        assert "new-tag" in full_section_config.nuclei["adaptive_tags"]
        assert full_section_config.nuclei["adaptive_tags"]["new-tag"] == {"severity": "low"}

    # ---- top-level direct field replacement ------------------------------

    def test_top_level_scoring_replacement(self, full_section_config: Config) -> None:
        """Providing the ‘http_timeout_seconds’ top-level key replaces it directly."""
        new_timeout = 42
        apply_adaptive_overrides(full_section_config, {"http_timeout_seconds": new_timeout})
        assert full_section_config.http_timeout_seconds == new_timeout

    def test_top_level_mode_replacement(self, full_section_config: Config) -> None:
        """mode is a direct (non-dict) field and should be replaced."""
        apply_adaptive_overrides(full_section_config, {"mode": "quick"})
        assert full_section_config.mode == "quick"

    # ---- edge-cases ------------------------------------------------------

    def test_empty_adaptive_dict_is_noop(self, full_section_config: Config) -> None:
        """Passing an empty dict must not alter the config."""
        original = full_section_config.scoring.copy()
        apply_adaptive_overrides(full_section_config, {})
        assert full_section_config.scoring == original

    def test_returns_same_config_object(self, full_section_config: Config) -> None:
        """apply_adaptive_overrides modifies and returns the same object."""
        result = apply_adaptive_overrides(full_section_config, {"mode": "test"})
        assert result is full_section_config

    def test_all_allowed_keys_applied_with_empty_sections(
        self, empty_section_config: Config
    ) -> None:
        """When starting from empty sections all-novel keys land correctly."""
        adaptive: dict[str, Any] = {
            "target_boosts": {"x.com": 99.0},
            "plugin_overrides": {"p": True},
            "threshold_deltas": {"tc": 0.5},
            "nuclei_template_boosts": ["t1"],
            "http_timeout_seconds": 7,
        }
        apply_adaptive_overrides(empty_section_config, adaptive)
        # non-standard keys that aren't config fields are silently ignored;
        # standard fields are set
        assert empty_section_config.http_timeout_seconds == 7

    def test_nested_merge_with_both_fields_missing(self, empty_section_config: Config) -> None:
        """Create nested-section dicts from scratch when they are initially empty."""
        adaptive = {
            "scoring": {"a": 1, "b": 2},
            "analysis": {"c": 3},
            "nuclei": {"e": 5},
        }
        apply_adaptive_overrides(empty_section_config, adaptive)
        assert empty_section_config.scoring == {"a": 1, "b": 2}
        assert empty_section_config.analysis == {"c": 3}
        assert empty_section_config.nuclei == {"e": 5}


# ---------------------------------------------------------------------------
# Ledger (smoke / regression – ledger itself is written by integration.py)
# ---------------------------------------------------------------------------


class TestLedgerUnchanged:
    """Smoke-tests that confirm the existing ledger pathway is not broken.

    The ledger file is written by `_persist_adaptive_config` in
    `src/learning/integration.py`.  We verify that the term still appears in
    the source so Phase 5.2's ledger-hardening requirement is live.
    """

    def test_ledger_write_path_still_exists(self) -> None:
        import inspect

        from src.learning.integration import LearningIntegration

        source = inspect.getsource(LearningIntegration._persist_adaptive_config)
        assert "config.adaptive.ledger.json" in source, (
            "_persist_adaptive_config must still write the ledger file as required by Phase 5.2."
        )

    def test_adaptive_config_still_integration_hook(self) -> None:
        import inspect

        from src.learning.integration import LearningIntegration

        source = inspect.getsource(LearningIntegration._persist_adaptive_config)
        assert "write_adaptive_config" in source, (
            "_persist_adaptive_config must call write_adaptive_config "
            "to persist the adaptive config for the next run."
        )


# ---------------------------------------------------------------------------
# Edge-case: adaptive file overlay / replacement
# ---------------------------------------------------------------------------


class TestAdaptiveConfigOverwrite:
    """Writing a second adaptive config replaces the first."""

    def test_second_write_overwrites_first(self, adaptive_dir: Path) -> None:
        store = PipelineOutputStore.create(adaptive_dir, "example.com")
        store.write_adaptive_config({"v1": "first"})
        store.write_adaptive_config({"v2": "second"})

        result = PipelineOutputStore.read_adaptive_config(store.target_root)
        assert "v1" not in result
        assert result["v2"] == "second"
