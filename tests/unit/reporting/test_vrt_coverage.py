"""Tests for VRT (Vulnerability Rating Taxonomy) coverage mapping.

Verifies that VRT catalog entries are correctly structured,
coverage calculations are accurate, and status assignments work.
"""

from pathlib import Path
from typing import Any

from src.core.models import Config
from src.reporting.vrt_coverage import P1_VRT_CATALOG, build_p1_vrt_coverage


def _make_config(**analysis_overrides: Any) -> Config:
    return Config(
        target_name="demo",
        output_dir=Path("output"),
        http_timeout_seconds=12,
        mode="fast",
        cache={},
        storage={},
        tools={},
        httpx={},
        gau={},
        waybackurls={},
        katana={},
        nuclei={},
        scoring={},
        filters={},
        screenshots={},
        analysis=analysis_overrides,
        review={},
        extensions={},
        concurrency={},
        output={},
        notifications={},
    )


class TestP1VrtCatalog:
    """Test P1 VRT catalog structure and completeness."""

    def test_catalog_not_empty(self) -> None:
        assert len(P1_VRT_CATALOG) > 0

    def test_all_entries_have_required_fields(self) -> None:
        required_fields = {
            "technical_severity",
            "vrt_category",
            "vulnerability_name",
            "variant",
            "direct_checks",
            "signal_checks",
            "notes",
        }
        for entry in P1_VRT_CATALOG:
            missing = required_fields - set(entry.keys())
            assert not missing, f"Entry missing fields: {missing}"

    def test_all_entries_are_p1(self) -> None:
        for entry in P1_VRT_CATALOG:
            assert entry["technical_severity"] == "P1"

    def test_entries_have_non_empty_category(self) -> None:
        for entry in P1_VRT_CATALOG:
            assert entry["vrt_category"], "vrt_category should not be empty"

    def test_entries_have_non_empty_vulnerability_name(self) -> None:
        for entry in P1_VRT_CATALOG:
            assert entry["vulnerability_name"], "vulnerability_name should not be empty"

    def test_entries_have_notes(self) -> None:
        for entry in P1_VRT_CATALOG:
            assert entry["notes"], "notes should not be empty"

    def test_direct_checks_is_list(self) -> None:
        for entry in P1_VRT_CATALOG:
            assert isinstance(entry["direct_checks"], list)

    def test_signal_checks_is_list(self) -> None:
        for entry in P1_VRT_CATALOG:
            assert isinstance(entry["signal_checks"], list)

    def test_has_idor_entry(self) -> None:
        categories = [e["vrt_category"] for e in P1_VRT_CATALOG]
        names = [e["vulnerability_name"] for e in P1_VRT_CATALOG]
        assert "Broken Access Control (BAC)" in categories
        assert "Insecure Direct Object References (IDOR)" in names

    def test_has_server_side_injection_entries(self) -> None:
        categories = [e["vrt_category"] for e in P1_VRT_CATALOG]
        assert "Server-Side Injection" in categories

    def test_has_sensitive_data_exposure_entry(self) -> None:
        categories = [e["vrt_category"] for e in P1_VRT_CATALOG]
        assert "Sensitive Data Exposure" in categories


class TestBuildP1VrtCoverage:
    """Test build_p1_vrt_coverage function."""

    def test_returns_expected_keys(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        assert "summary" in result
        assert "entries" in result
        assert "unsupported_entries" in result
        assert "disabled_entries" in result

    def test_summary_counts_match_catalog(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        summary = result["summary"]
        total = (
            summary.get("direct", 0)
            + summary.get("signal_only", 0)
            + summary.get("disabled", 0)
            + summary.get("unsupported", 0)
        )
        assert total == len(P1_VRT_CATALOG)

    def test_entries_count_matches_catalog(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        assert len(result["entries"]) == len(P1_VRT_CATALOG)

    def test_entry_status_is_valid(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        valid_statuses = {"direct", "signal_only", "disabled", "unsupported"}
        for entry in result["entries"]:
            assert entry["status"] in valid_statuses, f"Invalid status: {entry['status']}"

    def test_unsupported_entries_have_no_checks(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        for entry in result["unsupported_entries"]:
            assert entry["status"] == "unsupported"
            assert len(entry["active_checks"]) == 0

    def test_direct_entries_have_active_checks(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        for entry in result["entries"]:
            if entry["status"] == "direct":
                assert len(entry["active_checks"]) > 0

    def test_idor_has_direct_coverage(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        idor_entries = [e for e in result["entries"] if "IDOR" in e["vulnerability_name"]]
        assert len(idor_entries) > 0
        for entry in idor_entries:
            assert entry["status"] in ("direct", "signal_only")

    def test_sensitive_data_has_direct_coverage(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        sde_entries = [
            e for e in result["entries"] if "Disclosure of Secrets" in e["vulnerability_name"]
        ]
        assert len(sde_entries) > 0
        for entry in sde_entries:
            assert entry["status"] in ("direct", "signal_only")

    def test_smart_contract_entries_are_unsupported(self) -> None:
        config = _make_config()
        result = build_p1_vrt_coverage(config)
        sc_entries = [e for e in result["entries"] if "Smart Contract" in e["vrt_category"]]
        for entry in sc_entries:
            assert entry["status"] == "unsupported"
            assert len(entry["active_checks"]) == 0
