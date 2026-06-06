"""Configuration loader for the security testing pipeline.

Parses JSON configuration files into typed Config dataclass instances
with validation and default value handling.

Also provides adaptive-config helpers for Phase 5.2: loading persisted
learning adaptations from ``config.adaptive.json`` and shallow-merging them
on top of the base configuration object.
"""

import json
import os
import re
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline import CONFIG_DEFAULTS
from src.core.models import Config

_ENV_VAR_PATTERN = re.compile(r"\$\{([^}:]+)(?::([^}]*))?\}")

# Config fields whose values are themselves dicts — adaptive overrides for
# these fields are merged key-by-key rather than replacing the whole sub-dict.
_NESTED_MERGE_FIELDS: frozenset[str] = frozenset({"scoring", "analysis", "nuclei"})

_STORAGE_ENV_BACKEND = "PIPELINE_STORAGE_BACKEND"
_STORAGE_ENV_REDIS_URL = "PIPELINE_STORAGE_REDIS_URL"
_STORAGE_ENV_S3_BUCKET = "PIPELINE_STORAGE_S3_BUCKET"
_STORAGE_ENV_S3_PREFIX = "PIPELINE_STORAGE_S3_PREFIX"
_STORAGE_ENV_S3_ENDPOINT = "PIPELINE_STORAGE_S3_ENDPOINT"
_STORAGE_ENV_S3_REGION = "PIPELINE_STORAGE_S3_REGION"


def _interpolate_env_vars(value: str) -> str:
    """Replace ${VAR} and ${VAR:default} patterns with environment variable values.

    Supports:
    - ${VAR} - replaced with os.environ[VAR], raises error if not set
    - ${VAR:default} - replaced with os.environ[VAR] or 'default' if not set

    Args:
        value: String potentially containing env var patterns.

    Returns:
        String with env vars resolved.

    Raises:
        ValueError: If ${VAR} pattern is used and VAR is not set (no default).
    """

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)
        env_value = os.environ.get(var_name)
        if env_value is not None:
            return env_value
        if default is not None:
            return str(default)
        raise ValueError(
            f"Environment variable '{var_name}' is not set and no default provided. "
            f"Use ${{{var_name}:default_value}} syntax or set the variable."
        )

    return _ENV_VAR_PATTERN.sub(_replace, value)


def _resolve_storage_config(raw_storage: dict[str, Any]) -> dict[str, Any]:
    """Apply environment-variable backfill on the ``storage`` config section.

    Recognised variables:

    - ``PIPELINE_STORAGE_BACKEND`` — selects ``"local"``, ``"redis"`` or ``"s3"``
    - ``PIPELINE_STORAGE_REDIS_URL`` — Redis URL (required when backend=redis)
    - ``PIPELINE_STORAGE_S3_BUCKET`` — S3 bucket (required when backend=s3)
    - ``PIPELINE_STORAGE_S3_PREFIX`` — optional S3 key prefix
    - ``PIPELINE_STORAGE_S3_ENDPOINT`` / ``PIPELINE_STORAGE_S3_REGION`` — optional

    Values provided in the JSON config take precedence over environment
    variables. The dict is returned with at least ``backend`` set.
    """
    storage = dict(raw_storage or {})

    env_backend = os.environ.get(_STORAGE_ENV_BACKEND)
    if env_backend:
        storage.setdefault("backend", env_backend.lower())

    env_redis_url = os.environ.get(_STORAGE_ENV_REDIS_URL)
    if env_redis_url:
        storage.setdefault("redis_url", env_redis_url)

    for env_name, key in (
        (_STORAGE_ENV_S3_BUCKET, "bucket"),
        (_STORAGE_ENV_S3_PREFIX, "prefix"),
        (_STORAGE_ENV_S3_ENDPOINT, "endpoint_url"),
        (_STORAGE_ENV_S3_REGION, "region_name"),
    ):
        env_value = os.environ.get(env_name)
        if env_value:
            storage.setdefault(key, env_value)

    if not storage:
        storage["backend"] = "local"
    return storage


def load_config(path: Path) -> Config:
    """Load and validate a pipeline configuration from a JSON file.

    Args:
        path: Path to the JSON configuration file.

    Returns:
        Validated Config dataclass instance.

    Raises:
        ValueError: If the config is malformed or missing required fields.
    """
    raw_text = path.read_text(encoding="utf-8")
    raw_text = _interpolate_env_vars(raw_text)
    raw = json.loads(raw_text)
    if not isinstance(raw, dict):
        raise ValueError("Configuration file must contain a JSON object.")
    target_name = _require_text(raw, "target_name")
    output_dir = Path(_require_text(raw, "output_dir"))
    return Config(
        target_name=target_name,
        output_dir=output_dir,
        http_timeout_seconds=_positive_int(
            raw.get("http_timeout_seconds", CONFIG_DEFAULTS["http_timeout_seconds"]),
            "http_timeout_seconds",
        ),
        mode=str(raw.get("mode", CONFIG_DEFAULTS["mode"])).strip() or str(CONFIG_DEFAULTS["mode"]),
        cache=_optional_mapping(raw.get("cache"), "cache"),
        storage=_resolve_storage_config(_optional_mapping(raw.get("storage"), "storage")),
        tools=_optional_mapping(raw.get("tools"), "tools"),
        httpx=_optional_mapping(raw.get("httpx"), "httpx"),
        gau=_optional_mapping(raw.get("gau"), "gau"),
        waybackurls=_optional_mapping(raw.get("waybackurls"), "waybackurls"),
        katana=_optional_mapping(raw.get("katana"), "katana"),
        nuclei=_optional_mapping(raw.get("nuclei"), "nuclei"),
        scoring=_optional_mapping(raw.get("scoring"), "scoring"),
        filters=_optional_mapping(raw.get("filters"), "filters"),
        screenshots=_optional_mapping(raw.get("screenshots"), "screenshots"),
        analysis=_optional_mapping(raw.get("analysis"), "analysis"),
        review=_optional_mapping(raw.get("review"), "review"),
        extensions=_optional_mapping(raw.get("extensions"), "extensions"),
        concurrency=_optional_mapping(raw.get("concurrency"), "concurrency"),
        output=_optional_mapping(raw.get("output"), "output"),
        notifications=_optional_mapping(raw.get("notifications"), "notifications"),
    )


def _require_text(raw: dict[str, Any], key: str) -> str:
    value = str(raw.get(key, "")).strip()
    if not value:
        raise ValueError(f"Configuration field '{key}' is required.")
    return value


def _optional_mapping(value: object, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"Configuration field '{name}' must be an object.")
    return value


def _positive_int(value: object, name: str) -> int:
    if not isinstance(value, (int, float, str)):
        raise ValueError(f"Configuration field '{name}' must be an integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Configuration field '{name}' must be an integer.") from exc
    if parsed <= 0:
        raise ValueError(f"Configuration field '{name}' must be greater than zero.")
    return parsed


def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge *override* keys into a copy of *base*.

    Only top-level keys from *override* are applied; sub-values are
    replaced entirely rather than recursively merged.

    Args:
        base: The base dictionary to merge into.
        override: The dictionary whose keys take precedence.

    Returns:
        A new dictionary with merged contents.
    """
    return {**base, **override}


def apply_adaptive_overrides(config: Config, adaptive_dict: dict[str, Any]) -> Config:
    """Shallow-merge adaptive-learning overrides into an existing *config*.

    For the three nested-section fields ``scoring``, ``analysis``, and
    ``nuclei`` the adaptive dict values are merged on a per-key basis
    so individual sub-settings can be adjusted without wiping the rest
    of the section.  All other fields are replaced directly.

    The original *config* object is modified **in place** and also
    returned for convenience.

    Args:
        config: The ``Config`` dataclass instance produced by
            :func:`load_config`.
        adaptive_dict: The deserialised ``config.adaptive.json`` payload,
            typically the dict returned by
            ``PipelineOutputStore.read_adaptive_config()``.

    Returns:
        The same *config* instance with adaptive overrides applied.
    """
    if not adaptive_dict:
        return config

    for field_name in adaptive_dict:
        value = adaptive_dict[field_name]
        if field_name in _NESTED_MERGE_FIELDS:
            current = getattr(config, field_name, {})
            if not isinstance(current, dict):
                current = {}
            if isinstance(value, dict):
                merged = _merge_dict(current, value)
                setattr(config, field_name, merged)
            else:
                # Non-dict override on a nested field — replace outright.
                setattr(config, field_name, value)
        elif hasattr(config, field_name):
            setattr(config, field_name, value)

    return config
