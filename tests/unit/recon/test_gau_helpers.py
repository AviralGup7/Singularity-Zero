"""Coverage for gau provider-argument rewriting."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.recon.gau_helpers import replace_gau_provider_args, resolve_gau_extra_args


@pytest.mark.unit
def test_replace_providers_flag_and_equals_form() -> None:
    assert replace_gau_provider_args(["--o", "out.json"], "wayback,otx") == [
        "--o",
        "out.json",
        "--providers",
        "wayback,otx",
    ]
    assert replace_gau_provider_args(["--providers", "wayback"], "a,b") == [
        "--providers",
        "a,b",
    ]
    assert replace_gau_provider_args(["--providers=wayback", "--verbose"], "a,b") == [
        "--providers=a,b",
        "--verbose",
    ]


@pytest.mark.unit
def test_resolve_expands_empty_and_equals_wayback() -> None:
    empty = SimpleNamespace(gau={"extra_args": ["--verbose"]}, filters={})
    expanded = resolve_gau_extra_args(empty)
    assert expanded[-2:] == ["--providers", "wayback,commoncrawl,urlscan,otx"]
    equals = SimpleNamespace(gau={"extra_args": ["--providers=wayback"]}, filters={})
    assert "--providers=wayback,commoncrawl,urlscan,otx" in resolve_gau_extra_args(equals)
