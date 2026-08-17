"""Coverage for recon URL profile inference helpers."""

from __future__ import annotations

import pytest

from src.recon.scoring import infer_target_profile, query_parameter_names, resolve_priority_limit


@pytest.mark.unit
def test_infer_target_profile_empty() -> None:
    profile = infer_target_profile([])
    assert profile["total_urls"] == 0
    assert profile["api_heavy"] is False
    assert profile["api_ratio_percent"] == 0


@pytest.mark.unit
def test_infer_target_profile_flags_api_auth_params_and_files() -> None:
    urls = [
        "https://a.com/api/v1/users?id=1",
        "https://a.com/graphql",
        "https://a.com/login",
        "https://a.com/oauth/authorize",
        "https://a.com/upload?file=1",
        "https://a.com/about",
    ]
    profile = infer_target_profile(urls)
    assert profile["total_urls"] == 6
    assert profile["api_heavy"] is True
    assert profile["auth_heavy"] is True
    assert profile["parameter_heavy"] is True
    assert profile["file_heavy"] is True
    assert profile["api_ratio_percent"] >= 20


@pytest.mark.unit
def test_query_parameter_names_drops_tracking() -> None:
    names = query_parameter_names("https://a.com/p?id=1&utm_source=ad&q=x")
    assert names == ["id", "q"]
    assert query_parameter_names("https://a.com/p") == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("filters", "mode", "expected"),
    [
        ({"priority_limit": 25}, "fast", 25),
        ({"priority_limit": {"default": 40}}, "full", 40),
        ({"priority_limit": "nope"}, "fast", 100),
        ({}, "fast", 100),
    ],
)
def test_resolve_priority_limit(filters, mode: str, expected: int) -> None:
    assert resolve_priority_limit(filters, mode) == expected
