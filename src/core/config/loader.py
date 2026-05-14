"""Configuration loader for the security testing pipeline.

Parses JSON configuration files into typed Config dataclass instances
with validation and default value handling.
"""

import json
import os
import re
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline import CONFIG_DEFAULTS
from src.core.models import Config

_ENV_VAR_PATTERN = re.compile(r"\$\{([^}:]+)(?::([^}]*))?\}")


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
        storage=_optional_mapping(raw.get("storage"), "storage"),
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
