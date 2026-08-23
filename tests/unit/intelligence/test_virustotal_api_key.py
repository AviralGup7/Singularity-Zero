"""VirusTotal key resolution uses one canonical env var."""

from __future__ import annotations

from src.intel.feeds import is_feed_configured
from src.intelligence.feeds.virustotal import CANONICAL_VT_API_KEY_ENV, resolve_virustotal_api_key


def test_canonical_name_is_vt_api_key() -> None:
    assert CANONICAL_VT_API_KEY_ENV == "VT_API_KEY"


def test_canonical_wins_over_legacy_alias() -> None:
    env = {"VT_API_KEY": "canon", "VIRUSTOTAL_API_KEY": "legacy"}
    assert resolve_virustotal_api_key(env) == "canon"


def test_legacy_alias_used_when_canonical_missing() -> None:
    env = {"VIRUSTOTAL_API_KEY": "legacy"}
    assert resolve_virustotal_api_key(env) == "legacy"


def test_empty_when_neither_set() -> None:
    assert resolve_virustotal_api_key({}) == ""


def test_intel_feed_registry_accepts_either_name(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "legacy")
    assert is_feed_configured("virustotal") is True
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setenv("VT_API_KEY", "canon")
    assert is_feed_configured("virustotal") is True
