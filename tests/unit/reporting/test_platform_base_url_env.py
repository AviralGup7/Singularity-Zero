"""Regression: platform base_url must read env at construct time."""

from __future__ import annotations

import pytest

from src.reporting.platforms.bugzilla import MozillaClient
from src.reporting.platforms.msrc import MSRCAgent
from src.reporting.platforms.openbugbounty import OpenBugBountyClient


@pytest.mark.unit
def test_msrc_base_url_uses_current_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MSRC_BASE_URL", "https://msrc.example.test/")
    agent = MSRCAgent(api_key="k")
    assert agent.base_url == "https://msrc.example.test"
    override = MSRCAgent(api_key="k", base_url="https://override.test/")
    assert override.base_url == "https://override.test"
    monkeypatch.delenv("MSRC_BASE_URL", raising=False)
    assert MSRCAgent().base_url == "https://api.msrc.microsoft.com"
    assert MSRCAgent().ready is False


@pytest.mark.unit
def test_openbugbounty_and_mozilla_read_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENBUGBOUNTY_BASE_URL", "https://obb.example.test")
    monkeypatch.setenv("MOZILLA_BASE_URL", "https://bz.example.test")
    assert OpenBugBountyClient().base_url == "https://obb.example.test"
    assert MozillaClient().base_url == "https://bz.example.test"
