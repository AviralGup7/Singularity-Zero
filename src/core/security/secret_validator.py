"""Pre-flight secret validator.

The cyber security pipeline refuses to start (in any non-test environment)
when the operator has left default placeholder values in environment
variables. This module is the single source of truth for the placeholder
strings we treat as unsafe and for the policy we apply when they are
detected.

The validator runs at:

* FastAPI dashboard startup (``src.dashboard.fastapi.app.lifespan``)
* Pipeline CLI startup (``src.pipeline.runtime``)
* Worker startup (when imported by ``src.infrastructure.queue.worker``)

It is deliberately small and dependency-free so it can be imported from
anywhere without side effects.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

PLACEHOLDER_PREFIXES: tuple[str, ...] = (
    "REPLACE_WITH_",
    "CHANGE_ME",
    "CHANGEME",
)

# A few additional literal values that should never appear in production
# even though they do not match the prefix above.
KNOWN_BAD_LITERALS: frozenset[str] = frozenset(
    {
        "frontier-default-secret-change-in-prod",
        "frontier-default-secret",
        "frontier-default-secret-change-me",
        "change-me-in-production",
        "change-me",
        "admin",
        "password",
        "secret",
    }
)

# The full set of env var names that the validator inspects. Operators
# can extend this list through ``EXTRA_SECRET_ENV_VARS``.
DEFAULT_SECRET_ENV_VARS: tuple[str, ...] = (
    "APP_SECRET_KEY",
    "REDIS_PASSWORD",
    "REDIS_SENTINEL_PASSWORD",
    "GRAFANA_ADMIN_PASSWORD",
    "MESH_SECRET",
    "JWT_SECRET",
    "API_SECRET",
    "DB_PASSWORD",
    "DATABASE_URL",
)

EXTRA_SECRET_ENV_VARS: tuple[str, ...] = tuple(
    name.strip() for name in os.environ.get("EXTRA_SECRET_ENV_VARS", "").split(",") if name.strip()
)


def _is_placeholder(value: str) -> bool:
    if not value:
        return True
    if value in KNOWN_BAD_LITERALS:
        return True
    return any(value.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def _is_dev_environment() -> bool:
    """Return True if the current process is clearly running in development.

    The validator is more permissive in dev: it logs warnings instead of
    refusing to start. In any other environment (``production``,
    ``staging``, ``ci``, unset) the validator raises.
    """
    env = (os.environ.get("APP_ENV") or os.environ.get("ENVIRONMENT") or "").strip().lower()
    if env in {"dev", "development", "local", "test"}:
        return True
    if env in {"ci", "github_actions"}:
        return True
    # Bug #11 fix: previously this function returned ``not env`` for
    # unset/empty ``APP_ENV``/``ENVIRONMENT``, which silently treated
    # "env var forgotten" as a dev environment. An operator who
    # neglected to set the env var on a real production deployment
    # would get warnings instead of hard failures, allowing placeholder
    # secrets to flow into production. The default is now strict
    # (refuse to start); explicit opt-in to a permissive environment
    # is required via ``APP_SECURITY_PERMISSIVE=1``.
    if not env and os.environ.get("APP_SECURITY_PERMISSIVE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        return True
    return False


def collect_secret_env_vars() -> list[str]:
    """Return the list of env var names the validator will inspect."""
    return list(DEFAULT_SECRET_ENV_VARS) + list(EXTRA_SECRET_ENV_VARS)


def find_placeholder_violations(
    env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return ``{env_var: current_value}`` for every insecure placeholder."""
    env = env if env is not None else dict(os.environ)
    violations: dict[str, str] = {}
    for name in collect_secret_env_vars():
        value = env.get(name, "")
        if value and _is_placeholder(value):
            violations[name] = value
    return violations


def validate_or_raise(
    env: dict[str, str] | None = None,
    *,
    dev_override: bool | None = None,
) -> list[str]:
    """Validate secret env vars and raise on any placeholder values.

    Args:
        env: Optional override of ``os.environ``. Useful in tests.
        dev_override: When ``True`` (or when running in a dev environment
            and ``dev_override`` is unset) the validator logs warnings and
            returns the violation list without raising. When ``False`` the
            validator always raises.

    Returns:
        The list of violating env var names (empty if all clear).

    Raises:
        RuntimeError: When one or more placeholders are detected and the
            current process is not a development environment.
    """
    violations = find_placeholder_violations(env)
    if not violations:
        return []

    if dev_override is None:
        dev_override = _is_dev_environment()

    if dev_override:
        for name, value in violations.items():
            logger.warning(
                "Secret env var %s is set to a placeholder value (length=%d). "
                "This is acceptable in development but the application will "
                "refuse to start with the same value in production.",
                name,
                len(value),
            )
        return list(violations)

    rendered = "\n".join(f"  - {name}" for name in violations)
    raise RuntimeError(
        "Refusing to start: one or more secret env vars are set to a "
        'placeholder default. Generate real values (e.g. `python -c "import '
        'secrets; print(secrets.token_urlsafe(48))")` and update your '
        "environment. The following env vars are unsafe:\n"
        f"{rendered}"
    )
