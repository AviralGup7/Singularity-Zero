"""Coverage for shared subprocess helpers."""

from __future__ import annotations

import pytest

from src.core.utils.subprocess_utils import (
    SHELL_META,
    _clean_env,
    _coerce_output_text,
    _get_creationflags,
)


@pytest.mark.unit
@pytest.mark.parametrize("token", [";", "|", "&", "`", "$", "\n", "\r"])
def test_shell_meta_detects_operators(token: str) -> None:
    assert SHELL_META.search(f"echo{token}id")
    assert SHELL_META.search("echo hello") is None


@pytest.mark.unit
def test_clean_env_and_coerce() -> None:
    assert _clean_env(None) == {}
    cleaned = _clean_env({"A": "1", "B": "ok"})
    assert cleaned == {"A": "1", "B": "ok"}
    assert _coerce_output_text(None) == ""
    assert _coerce_output_text(b"abc") == "abc"
    assert _coerce_output_text("xyz") == "xyz"
    assert isinstance(_get_creationflags(), int)
