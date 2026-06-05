"""Tests for the secret placeholder validator."""

import pytest

from src.core.security import secret_validator
from src.core.security.secret_validator import (
    KNOWN_BAD_LITERALS,
    PLACEHOLDER_PREFIXES,
    collect_secret_env_vars,
    find_placeholder_violations,
    validate_or_raise,
)


def test_collect_secret_env_vars_includes_known_secrets():
    names = collect_secret_env_vars()
    assert "APP_SECRET_KEY" in names
    assert "REDIS_PASSWORD" in names
    assert "GRAFANA_ADMIN_PASSWORD" in names


def test_placeholder_prefixes_include_replace_with():
    assert any("REPLACE_WITH" in p for p in PLACEHOLDER_PREFIXES)


def test_known_bad_literals_include_admin_and_password():
    assert "admin" in KNOWN_BAD_LITERALS
    assert "password" in KNOWN_BAD_LITERALS
    assert "secret" in KNOWN_BAD_LITERALS


def test_find_placeholder_violations_detects_replace_with():
    env = {
        "APP_SECRET_KEY": "REPLACE_WITH_RANDOM",
        "REDIS_PASSWORD": "x" * 32,
        "GRAFANA_ADMIN_PASSWORD": "y" * 32,
    }
    bad = find_placeholder_violations(env)
    assert "APP_SECRET_KEY" in bad
    assert "REDIS_PASSWORD" not in bad
    assert "GRAFANA_ADMIN_PASSWORD" not in bad


def test_find_placeholder_violations_detects_known_bad_literal():
    env = {
        "APP_SECRET_KEY": "x" * 32,
        "REDIS_PASSWORD": "admin",
        "GRAFANA_ADMIN_PASSWORD": "y" * 32,
    }
    bad = find_placeholder_violations(env)
    assert "REDIS_PASSWORD" in bad


def test_find_placeholder_violations_passes_real_secret():
    env = {
        "APP_SECRET_KEY": "a" * 32,
        "REDIS_PASSWORD": "b" * 24,
        "GRAFANA_ADMIN_PASSWORD": "c" * 24,
    }
    assert find_placeholder_violations(env) == {}


def test_find_placeholder_violations_ignores_unrelated_env():
    env = {"PATH": "/usr/bin", "HOME": "/root", "USER": "ci"}
    assert find_placeholder_violations(env) == {}


def test_find_placeholder_violations_empty_for_unset():
    """If the env var is not in the dict at all, it is not a violation."""
    assert find_placeholder_violations({}) == {}


def test_validate_or_raise_in_dev_returns_violations_without_raising(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    env = {"APP_SECRET_KEY": "REPLACE_WITH_RANDOM"}
    result = validate_or_raise(env=env)
    assert "APP_SECRET_KEY" in result


def test_validate_or_raise_in_production_raises(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError) as exc:
        validate_or_raise(env={"APP_SECRET_KEY": "REPLACE_WITH_RANDOM"})
    assert "APP_SECRET_KEY" in str(exc.value)


def test_validate_or_raise_passes_in_production_with_real_secrets(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    env = {
        "APP_SECRET_KEY": "x" * 32,
        "REDIS_PASSWORD": "y" * 24,
        "GRAFANA_ADMIN_PASSWORD": "z" * 24,
    }
    assert validate_or_raise(env=env) == []


def test_validate_or_raise_dev_override_forces_warn(monkeypatch):
    """dev_override=True must always warn instead of raising, regardless of env."""
    monkeypatch.setenv("APP_ENV", "production")
    result = validate_or_raise(
        env={"APP_SECRET_KEY": "REPLACE_WITH_RANDOM"},
        dev_override=True,
    )
    assert "APP_SECRET_KEY" in result


def test_validate_or_raise_no_dev_override_always_raises(monkeypatch):
    """dev_override=False must always raise, even in dev environment."""
    monkeypatch.setenv("APP_ENV", "development")
    with pytest.raises(RuntimeError):
        validate_or_raise(
            env={"APP_SECRET_KEY": "REPLACE_WITH_RANDOM"},
            dev_override=False,
        )


def test_extra_secret_env_vars_via_env(monkeypatch):
    """Operators can extend the inspect list via EXTRA_SECRET_ENV_VARS."""
    monkeypatch.setenv("EXTRA_SECRET_ENV_VARS", "CUSTOM_TENANT_KEY")
    # Reload to pick up the new env var
    import importlib

    importlib.reload(secret_validator)
    try:
        names = secret_validator.collect_secret_env_vars()
        assert "CUSTOM_TENANT_KEY" in names
    finally:
        monkeypatch.delenv("EXTRA_SECRET_ENV_VARS", raising=False)
        importlib.reload(secret_validator)
