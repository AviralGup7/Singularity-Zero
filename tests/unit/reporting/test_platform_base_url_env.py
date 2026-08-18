"""Regression + similar-case: all platform clients read base_url at construct time."""

from __future__ import annotations

import pytest

from src.reporting.platforms.apple import AppleClient
from src.reporting.platforms.aws import AWSClient
from src.reporting.platforms.base import resolve_base_url
from src.reporting.platforms.bugcrowd import BugcrowdClient
from src.reporting.platforms.bugzilla import MozillaClient
from src.reporting.platforms.googlevrp import GoogleVRPClient
from src.reporting.platforms.govdefense import GovDefenseClient
from src.reporting.platforms.hackerone import HackerOneClient
from src.reporting.platforms.intigriti import IntigritiClient
from src.reporting.platforms.meta import MetaClient
from src.reporting.platforms.msrc import MSRCAgent
from src.reporting.platforms.openbugbounty import OpenBugBountyClient
from src.reporting.platforms.synack import SynackClient
from src.reporting.platforms.yeswehack import YesWeHackClient

_CASES: list[tuple[type, str, str, str]] = [
    (MSRCAgent, "MSRC_BASE_URL", "https://api.msrc.microsoft.com", "https://msrc.example.test"),
    (
        OpenBugBountyClient,
        "OPENBUGBOUNTY_BASE_URL",
        "https://www.openbugbounty.org",
        "https://obb.example.test",
    ),
    (MozillaClient, "MOZILLA_BASE_URL", "https://bugzilla.mozilla.org", "https://bz.example.test"),
    (AppleClient, "APPLE_BASE_URL", "https://api.apple-security.com", "https://apple.example.test"),
    (
        AWSClient,
        "AWS_BASE_URL",
        "https://security-report.aws.amazon.com",
        "https://aws.example.test",
    ),
    (BugcrowdClient, "BUGCROWD_BASE_URL", "https://api.bugcrowd.com", "https://bc.example.test"),
    (HackerOneClient, "HACKERONE_BASE_URL", "https://api.hackerone.com", "https://h1.example.test"),
    (
        IntigritiClient,
        "INTIGRITI_BASE_URL",
        "https://api.intigriti.com",
        "https://int.example.test",
    ),
    (MetaClient, "META_BASE_URL", "https://graph.facebook.com", "https://meta.example.test"),
    (SynackClient, "SYNACK_BASE_URL", "https://api.synack.com", "https://syn.example.test"),
    (
        YesWeHackClient,
        "YESWEHACK_BASE_URL",
        "https://api.yeswehack.com",
        "https://ywh.example.test",
    ),
    (
        GoogleVRPClient,
        "GOOGLE_VRP_BASE_URL",
        "https://issuetracker.googleapis.com",
        "https://gvrp.example.test",
    ),
    (
        GovDefenseClient,
        "CISA_BASE_URL",
        "https://vulnerability-disclosure.cisa.gov",
        "https://cisa.example.test",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(("cls", "env_name", "default", "override"), _CASES)
def test_platform_base_url_reads_env_at_construct_time(
    monkeypatch: pytest.MonkeyPatch,
    cls: type,
    env_name: str,
    default: str,
    override: str,
) -> None:
    monkeypatch.setenv(env_name, override + "/")
    client = cls()
    assert client.base_url == override
    explicit = cls(base_url="https://explicit.example.test/")
    assert explicit.base_url == "https://explicit.example.test"
    monkeypatch.delenv(env_name, raising=False)
    assert cls().base_url == default


@pytest.mark.unit
def test_resolve_base_url_helper() -> None:
    assert resolve_base_url("https://a.test/", "UNUSED", "https://d.test") == "https://a.test"
    assert resolve_base_url(None, "UNUSED", "https://d.test/") == "https://d.test"
