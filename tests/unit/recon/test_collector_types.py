"""Tests for :mod:`src.recon.collectors.types` (CollectorMeta + CollectorStatus)."""

from __future__ import annotations

import pytest

from src.recon.collectors.types import (
    CollectorMeta,
    CollectorStatus,
    coerce_meta,
    merge_meta,
)


def _basic(**overrides):
    base = dict(
        status=CollectorStatus.OK,
        duration_seconds=1.5,
        new_urls=10,
        errors=0,
        hosts_scanned=2,
        provider_name="unit-test",
    )
    base.update(overrides)
    return CollectorMeta(**base)


class TestCollectorMetaDictCompatibility:
    def test_get_returns_value(self) -> None:
        meta = _basic()
        assert meta.get("new_urls") == 10
        assert meta.get("missing", "fallback") == "fallback"

    def test_getitem_returns_value(self) -> None:
        meta = _basic()
        assert meta["status"] == "ok"
        assert meta["provider_name"] == "unit-test"

    def test_contains(self) -> None:
        meta = _basic()
        assert "new_urls" in meta
        assert "missing" not in meta

    def test_items_keys_values(self) -> None:
        meta = _basic()
        items = dict(meta.items())
        assert items["new_urls"] == 10
        assert "status" in meta.keys()
        assert 10 in meta.values()

    def test_iter_yields_known_keys(self) -> None:
        meta = _basic()
        keys = list(iter(meta))
        assert "status" in keys
        assert "new_urls" in keys

    def test_status_string_equality(self) -> None:
        meta = _basic()
        assert meta["status"] == "ok"
        assert meta["status"] == CollectorStatus.OK
        assert meta.status == "ok"

    def test_legacy_dict_construction_coerces(self) -> None:
        meta = coerce_meta({"status": "ok", "new_urls": 3, "errors": 0})
        assert isinstance(meta, CollectorMeta)
        assert meta.new_urls == 3
        assert meta["status"] == "ok"

    def test_legacy_unknown_keys_go_to_extras(self) -> None:
        meta = coerce_meta(
            {"status": "ok", "new_urls": 1, "pages_fetched": 12, "scripts_found": 4}
        )
        # The unknown fields live in ``extras`` AND are surfaced through
        # the dict-like API (``__getitem__`` / ``__contains__``) for
        # backwards compatibility.
        assert meta.extras["pages_fetched"] == 12
        assert meta.extras["scripts_found"] == 4
        assert meta["pages_fetched"] == 12
        assert "pages_fetched" in meta

    def test_coerce_existing_passthrough(self) -> None:
        meta = _basic()
        assert coerce_meta(meta) is meta

    def test_coerce_none_returns_empty(self) -> None:
        meta = coerce_meta(None, provider_name="p")
        assert meta.provider_name == "p"
        assert meta.status == CollectorStatus.UNKNOWN

    def test_coerce_non_mapping_sets_raw_extra(self) -> None:
        meta = coerce_meta(42, provider_name="p")
        assert meta.extras["raw"] == 42

    def test_to_dict_roundtrip(self) -> None:
        meta = _basic()
        d = meta.to_dict()
        assert isinstance(d, dict)
        assert d["new_urls"] == 10
        # Status comes back as a string (CollectorStatus subclasses str).
        assert d["status"] == "ok"


class TestCollectorMetaMutability:
    def test_frozen_dataclass_raises_on_assignment(self) -> None:
        meta = _basic()
        with pytest.raises(Exception):
            meta.new_urls = 99  # type: ignore[misc]

    def test_with_updates_returns_new_instance(self) -> None:
        meta = _basic()
        updated = meta.with_updates(new_urls=42)
        assert updated is not meta
        assert updated.new_urls == 42
        assert meta.new_urls == 10  # original unchanged

    def test_with_updates_can_set_extras(self) -> None:
        meta = _basic()
        updated = meta.with_updates(extras={"key": "value"})
        assert updated.extras["key"] == "value"

    def test_merge_meta_sums(self) -> None:
        a = _basic(new_urls=5, errors=1, hosts_scanned=2, duration_seconds=1.0)
        b = _basic(new_urls=3, errors=2, hosts_scanned=4, duration_seconds=2.0)
        merged = merge_meta(a, b)
        assert merged.new_urls == 8
        assert merged.errors == 3
        assert merged.hosts_scanned == 6
        assert merged.duration_seconds == pytest.approx(3.0)
        assert merged.status == CollectorStatus.OK

    def test_merge_meta_warnings_concatenated(self) -> None:
        a = _basic(warnings=["w1", "w2"])
        b = _basic(warnings=["w3"])
        merged = merge_meta(a, b)
        # Warnings are stored as a tuple (de-duplicated, order preserved).
        assert tuple(merged.warnings) == ("w1", "w2", "w3")
        # The dict-like API also surfaces them as a list.
        assert merged["warnings"] == ["w1", "w2", "w3"]

    def test_merge_meta_status_prefers_failure(self) -> None:
        # merge_meta prefers OK when *any* of the inputs is OK — this is
        # the right behaviour for an aggregator that wants to report
        # success even if some sub-iterations errored (they still
        # contributed URLs).  We verify both directions:
        a = _basic(status=CollectorStatus.OK)
        b = _basic(status=CollectorStatus.ERROR)
        merged = merge_meta(a, b)
        assert merged.status == CollectorStatus.OK

        # All-error inputs collapse to ERROR.
        c = _basic(status=CollectorStatus.ERROR)
        d = _basic(status=CollectorStatus.TIMEOUT)
        merged_all_bad = merge_meta(c, d)
        assert merged_all_bad.status in (CollectorStatus.ERROR, CollectorStatus.TIMEOUT)

    def test_is_failure_detection(self) -> None:
        assert _basic().is_failure() is False
        assert _basic(status=CollectorStatus.ERROR).is_failure() is True
        assert _basic(status=CollectorStatus.TIMEOUT).is_failure() is True
        assert _basic(status=CollectorStatus.AUTH_FAILED).is_failure() is True
        assert _basic(status=CollectorStatus.EMPTY).is_failure() is False


class TestCollectorStatus:
    def test_string_enum_values(self) -> None:
        assert CollectorStatus.OK.value == "ok"
        assert CollectorStatus.SKIPPED_CIRCUIT_OPEN.value == "skipped_circuit_open"
        assert CollectorStatus.RATE_LIMITED.value == "rate_limited"
