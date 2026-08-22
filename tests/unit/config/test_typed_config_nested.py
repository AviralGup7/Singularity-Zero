"""Regression tests for nested TypedConfig coercion and adaptive merge.

The previous _from_dict implementation passed each nested mapping as the
first positional dataclass field (e.g. CacheConfig.enabled became the
whole cache dict). These tests lock the recursive fix against
configs/config.example.json and ValidatedPipelineConfig.
"""

from __future__ import annotations

from pathlib import Path

from src.core.config.typed_config import (
    CacheConfig,
    FilterConfig,
    HttpxConfig,
    NucleiConfig,
    ScoringConfig,
    ValidatedPipelineConfig,
    apply_adaptive_overrides,
    load_config,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLE_CONFIG = REPO_ROOT / "configs" / "config.example.json"


def test_example_json_nested_sections_are_typed() -> None:
    cfg = load_config(EXAMPLE_CONFIG)

    assert isinstance(cfg, ValidatedPipelineConfig)
    assert isinstance(cfg.cache, CacheConfig)
    assert isinstance(cfg.httpx, HttpxConfig)
    assert isinstance(cfg.nuclei, NucleiConfig)
    assert isinstance(cfg.scoring, ScoringConfig)
    assert isinstance(cfg.filters, FilterConfig)


def test_example_json_cache_httpx_nuclei_scoring_values() -> None:
    cfg = load_config(EXAMPLE_CONFIG)

    assert cfg.cache.enabled is True
    assert isinstance(cfg.cache.enabled, bool)
    assert cfg.cache.ttl_hours == 24
    assert cfg.cache.max_size_mb == 500

    assert cfg.httpx.threads == 50
    assert isinstance(cfg.httpx.threads, int)
    assert cfg.httpx.extra_args == []

    assert cfg.nuclei.severity == ["medium", "high", "critical"]
    assert cfg.nuclei.timeout_seconds == 120
    assert cfg.nuclei.extra_args == ["-rate-limit", "50"]
    assert cfg.nuclei.threads == 25

    assert cfg.scoring.custom_keyword_bonus == 2
    assert cfg.scoring.weights["admin"] == 10
    assert cfg.scoring.weights["idor"] == 9
    assert cfg.scoring.contexts["api_heavy"]["bonus"] == 3
    assert "/api/" in cfg.scoring.contexts["api_heavy"]["keywords"]

    assert cfg.filters.adaptive_url_cap is True
    assert cfg.filters.max_collected_urls == 1400
    assert cfg.filters.archive_host_threshold == 250
    assert isinstance(cfg.filters.priority_limit, dict)
    assert cfg.filters.priority_limit["default"] == 50


def test_example_json_preserves_unknown_nuclei_keys_for_consumers() -> None:
    cfg = load_config(EXAMPLE_CONFIG)

    assert cfg.nuclei.get("dedupe_history", False) is True
    assert cfg.nuclei.get("feedback_target_limit", 0) == 40
    assert "redirect" in cfg.nuclei.get("adaptive_tags", {})
    assert cfg.httpx.get("threads") == 50
    assert cfg.filters.get("run_headless_on_spa", True) is True


def test_from_dict_does_not_stuff_mapping_into_first_field() -> None:
    cfg = ValidatedPipelineConfig._from_dict(
        {
            "target_name": "unit",
            "output_dir": "output",
            "cache": {"enabled": False, "ttl_hours": 3},
            "httpx": {"threads": 7, "extra_args": ["-silent"]},
            "nuclei": {"severity": ["critical"], "threads": 4, "extra_args": ["-rl", "10"]},
            "scoring": {"custom_keyword_bonus": 8, "weights": {"api": 11}},
        }
    )

    assert cfg.cache.enabled is False
    assert cfg.cache.ttl_hours == 3
    assert cfg.httpx.threads == 7
    assert cfg.httpx.extra_args == ["-silent"]
    assert cfg.nuclei.severity == ["critical"]
    assert cfg.nuclei.threads == 4
    assert cfg.scoring.custom_keyword_bonus == 8
    assert cfg.scoring.weights["api"] == 11
    assert cfg.scoring.weights["ssrf"] == 5


def test_adaptive_overrides_keep_typed_nested_sections() -> None:
    cfg = load_config(EXAMPLE_CONFIG)
    original_admin = cfg.scoring.weights["admin"]
    original_severity = list(cfg.nuclei.severity)

    apply_adaptive_overrides(
        cfg,
        {
            "scoring": {
                "custom_keyword_bonus": 9,
                "weights": {"api": 99},
                "target_boosts": {"x": 2.0},
            },
            "nuclei": {"severity": ["critical"], "adaptive_tags": {"xss": ["xss"]}},
            "cache": {"enabled": False},
            "analysis": {"plugin_intensity": 2.5},
        },
    )

    assert isinstance(cfg.scoring, ScoringConfig)
    assert isinstance(cfg.nuclei, NucleiConfig)
    assert isinstance(cfg.cache, CacheConfig)
    assert cfg.scoring.custom_keyword_bonus == 9
    assert cfg.scoring.weights["api"] == 99
    assert cfg.scoring.weights["admin"] == original_admin
    assert cfg.scoring.get("target_boosts") == {"x": 2.0}
    assert cfg.nuclei.severity == ["critical"]
    assert cfg.nuclei.timeout_seconds == 120
    assert original_severity != ["critical"]
    assert cfg.nuclei.get("adaptive_tags")["xss"] == ["xss"]
    assert cfg.nuclei.get("dedupe_history") is True
    assert cfg.cache.enabled is False
    assert cfg.cache.ttl_hours == 24
    assert cfg.analysis["plugin_intensity"] == 2.5


def test_adaptive_overrides_do_not_replace_legacy_dict_sections() -> None:
    from src.core.models.config import Config

    config = Config(
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
        analysis={"plugin_overrides": {"plugin_a": "on"}},
        filters={},
        screenshots={},
        review={},
        extensions={},
        concurrency={},
        output={},
        notifications={},
    )

    apply_adaptive_overrides(config, {"scoring": {"new_boost_key": 10.0}})
    assert config.scoring["target_boosts"] == {"old.com": 1.5}
    assert config.scoring["new_boost_key"] == 10.0
