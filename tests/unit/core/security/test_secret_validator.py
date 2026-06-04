"""Tests for the secret placeholder validator."""

import importlib
import os

import pytest

from src.core.security import secret_validator
from src.core.security.secret_validator import (
    collect_secret_env_vars,
    find_placeholder_violations,
    validate_or_raise,
)


def test_collect_secret_env_vars_includes_known_secrets():
    names = collect_secret_env_vars()
    assert "APP_SECRET_KEY" in names
    assert "REDIS_PASSWORD" in names
    assert "GRAFANA_ADMIN_PASSWORD" in names


def test_find_placeholder_violations_detects_replace_with():
    env = {
        "APP_SECRET_KEY": "REPLACE_WITH_RANDOM",
        "REDIS_PASSWORD": "changeme",
        "GRAFANA_ADMIN_PASSWORD": "admin",
    }
    bad = find_placeholder_violations(env)
    assert "APP_SECRET_KEY" in bad
    assert "REDIS_PASSWORD" in bad
    assert "GRAFANA_ADMIN_PASSWORD" in bad


def test_find_placeholder_violations_passes_real_secret():
    env = {
        "APP_SECRET_KEY": "a" * 32,
        "REDIS_PASSWORD": "b" * 24,
        "GRAFANA_ADMIN_PASSWORD": "c" * 24,
    }
    assert find_placeholder_violations(env) == []


def test_find_placeholder_violations_ignores_unrelated_env():
    env = {"PATH": "/usr/bin", "HOME": "/root", "USER": "ci"}
    assert find_placeholder_violations(env) == []


def test_validate_or_raise_in_dev_warns_only(monkeypatch, caplog):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("APP_SECRET_KEY", "REPLACE_WITH_RANDOM")
    monkeypatch.setenv("REDIS_PASSWORD", "changeme")
    # Should NOT raise in dev
    validate_or_raise(env={"APP_SECRET_KEY": "REPLACE_WITH_RANDOM", "REDIS_PASSWORD": "changeme"})


def test_validate_or_raise_in_production_raises(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError) as exc:
        validate_or_raise(env={"APP_SECRET_KEY": "REPLACE_WITH_RANDOM"})
    assert "APP_SECRET_KEY" in str(exc.value)


def test_validate_or_raise_passes_in_production_with_real_secrets():
    env = {
        "APP_SECRET_KEY": "x" * 32,
        "REDIS_PASSWORD": "y" * 24,
        "GRAFANA_ADMIN_PASSWORD": "z" * 24,
    }
    # No exception in any environment when secrets are real
    validate_or_raise(env=env)


def test_validate_or_raise_env_var_override(monkeypatch):
    """The operator can override the validator allowlist via env var."""
    monkeypatch.setenv("SECRET_VALIDATOR_ALLOWLIST", "APP_SECRET_KEY")
    env = {"APP_SECRET_KEY": "REPLACE_WITH_RANDOM", "REDIS_PASSWORD": "changeme"}
    # APP_SECRET_KEY allowed; REDIS_PASSWORD still bad
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError) as exc:
        validate_or_raise(env=env)
    assert "REDIS_PASSWORD" in str(exc.value)
    assert "APP_SECRET_KEY" not in str(exc.value)
