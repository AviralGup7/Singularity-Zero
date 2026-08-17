from __future__ import annotations

import json
import os
import re
from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any, get_args, get_origin, get_type_hints

if TYPE_CHECKING:  # pragma: no cover - typing only
    from src.core.models.config import Config


# ============================================================
# Environment Variable Binding
# ============================================================

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
    """Apply environment-variable backfill on the ``storage`` config section."""
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


def _coerce_value(value: Any, target_type: type) -> Any:
    """Coerce value to target type."""
    if value is None:
        return None

    origin = get_origin(target_type)
    args = get_args(target_type)

    if target_type is list or origin is list:
        if not isinstance(value, (list, tuple, set)):
            raise ValueError(f"Expected list value, got {type(value).__name__}")
        item_type = args[0] if args else str
        return [_coerce_value(v, item_type) for v in value]
    if target_type is dict or origin is dict:
        if not isinstance(value, dict):
            raise ValueError(f"Expected dict value, got {type(value).__name__}")
        key_type, val_type = args if len(args) == 2 else (str, str)
        return {_coerce_value(k, key_type): _coerce_value(v, val_type) for k, v in value.items()}
    if origin is type(None) or target_type is type(None):
        return value
    if target_type is Path:
        return Path(value)
    if target_type is bool:
        if isinstance(value, str):
            return value.lower() in ("1", "true", "yes", "on")
        return bool(value)
    return target_type(value)


class TypedConfig:
    """Base class for type-safe, validated configuration."""

    @classmethod
    def load(cls, path: Path | str) -> TypedConfig:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> TypedConfig:
        kwargs = {}
        hints = get_type_hints(cls)

        for f in fields(cls):
            if f.name not in data:
                if f.default is not MISSING:
                    kwargs[f.name] = f.default
                elif f.default_factory is not MISSING:
                    kwargs[f.name] = f.default_factory()
                else:
                    raise ValueError(f"Missing required config field: {f.name}")
            else:
                kwargs[f.name] = _coerce_value(data[f.name], hints.get(f.name, Any))

        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")


# ============================================================
# Pipeline Configuration Models
# ============================================================

@dataclass
class CacheConfig(TypedConfig):
    enabled: bool = True
    ttl_hours: int = 24
    max_size_mb: int = 500


@dataclass
class NucleiConfig(TypedConfig):
    severity: list[str] = field(default_factory=lambda: ["critical", "high"])
    threads: int = 25
    timeout_seconds: int = 120
    extra_args: list[str] = field(default_factory=list)
    rate_limit: int = 150
    templates_dir: str | None = None


@dataclass
class HttpxConfig(TypedConfig):
    threads: int = 50
    timeout_seconds: int = 10
    follow_redirects: bool = True
    extra_args: list[str] = field(default_factory=list)


@dataclass
class ScoringConfig(TypedConfig):
    weights: dict[str, int] = field(default_factory=lambda: {
        "api": 3,
        "auth": 4,
        "redirect": 3,
        "param": 2,
        "sensitive": 5,
        "idor": 4,
        "ssrf": 5,
        "xss": 4,
        "sqli": 5,
    })
    custom_keyword_bonus: int = 2
    contexts: dict[str, dict] = field(default_factory=lambda: {
        "api_heavy": {"bonus": 3, "keywords": ["/api/", "/v1/", "/v2/", "graphql"]},
        "auth_heavy": {"bonus": 4, "keywords": ["/auth", "/login", "/oauth", "token", "session"]},
        "file_heavy": {"bonus": 3, "keywords": ["upload", "download", "file", "export"]},
    })
    modes: dict[str, dict] = field(default_factory=lambda: {
        "full": {"param_bonus": 2, "parameter_keywords": ["id", "user", "account"], "path_keywords": ["/api/", "/admin/"]},
        "idor": {"param_bonus": 5, "parameter_keywords": ["id", "user_id", "account_id"], "path_keywords": []},
        "ssrf": {"param_bonus": 5, "parameter_keywords": ["url", "uri", "dest", "redirect"], "path_keywords": []},
    })


@dataclass
class FilterConfig(TypedConfig):
    ignore_extensions: list[str] = field(default_factory=lambda: [
        "css", "js", "png", "jpg", "jpeg", "gif", "svg", "woff", "woff2",
        "ttf", "eot", "ico", "pdf", "zip", "gz", "tar", "rar", "7z",
        "mp4", "webm", "mp3", "wav", "ogg", "flac", "avi", "mov",
    ])
    priority_keywords: list[str] = field(default_factory=lambda: [
        "admin", "api", "auth", "login", "oauth", "token", "session",
        "password", "reset", "register", "signup", "register",
    ])
    priority_limit: int = 100
    adaptive_url_cap: bool = True
    archive_host_threshold: int = 250
    archive_batch_size: int = 20
    max_collected_urls: int = 5000


@dataclass
class ValidatedPipelineConfig(TypedConfig):
    """Canonical pipeline configuration with typed nested sections.

    This is the v2 canonical configuration model. It replaces the legacy
    ``Config`` dataclass from ``src.core.models.config``.
    """
    target_name: str
    output_dir: str
    http_timeout_seconds: int = 12
    mode: str = "default"
    cache: CacheConfig = field(default_factory=CacheConfig)
    storage: dict = field(default_factory=dict)
    tools: dict = field(default_factory=dict)
    httpx: HttpxConfig = field(default_factory=HttpxConfig)
    gau: dict = field(default_factory=dict)
    waybackurls: dict = field(default_factory=dict)
    katana: dict = field(default_factory=dict)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    filters: FilterConfig = field(default_factory=FilterConfig)
    screenshots: dict = field(default_factory=dict)
    analysis: dict = field(default_factory=dict)
    review: dict = field(default_factory=dict)
    extensions: dict = field(default_factory=dict)
    concurrency: dict = field(default_factory=dict)
    output: dict = field(default_factory=dict)
    notifications: dict = field(default_factory=dict)
    _resume_from: str | None = field(default=None, repr=False, compare=False)
    scope_entries: list[str] = field(default_factory=list)

    @property
    def output_path(self) -> Path:
        return Path(self.output_dir)

    @classmethod
    def from_legacy_config(cls, config: Config) -> ValidatedPipelineConfig:
        """Create a ValidatedPipelineConfig from the legacy Config dataclass.

        This is the canonical migration bridge during the v2 config unification.
        """
        from src.core.models.config import Config as LegacyConfig

        if not isinstance(config, LegacyConfig):
            raise TypeError(f"Expected legacy Config, got {type(config).__name__}")

        return cls(
            target_name=config.target_name,
            output_dir=str(config.output_dir),
            http_timeout_seconds=config.http_timeout_seconds,
            mode=config.mode,
            cache=CacheConfig(**(config.cache or {})),
            storage=config.storage or {},
            tools=config.tools or {},
            httpx=HttpxConfig(**(config.httpx or {})),
            gau=config.gau or {},
            waybackurls=config.waybackurls or {},
            katana=config.katana or {},
            nuclei=NucleiConfig(**(config.nuclei or {})),
            scoring=ScoringConfig(**(config.scoring or {})),
            filters=FilterConfig(**(config.filters or {})),
            screenshots=config.screenshots or {},
            analysis=config.analysis or {},
            review=config.review or {},
            extensions=config.extensions or {},
            concurrency=config.concurrency or {},
            output=config.output or {},
            notifications=config.notifications or {},
            _resume_from=getattr(config, "_resume_from", None),
            scope_entries=getattr(config, "scope_entries", []),
        )


# Alias for plan compatibility — the canonical public name is PipelineConfig.
PipelineConfig = ValidatedPipelineConfig


# ============================================================
# Private helpers (re-exported from loader.py for backward compat)
# ============================================================

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


# ============================================================
# Registration helpers
# ============================================================

def load_config(path: Path | str) -> ValidatedPipelineConfig:
    """Load configuration from a JSON file with env var interpolation.

    Args:
        path: Path to the JSON configuration file.

    Returns:
        Loaded ValidatedPipelineConfig instance.
    """
    raw_text = Path(path).read_text(encoding="utf-8")
    raw_text = _interpolate_env_vars(raw_text)
    raw = json.loads(raw_text)
    if not isinstance(raw, dict):
        raise ValueError("Configuration file must contain a JSON object.")
    raw = _resolve_storage_config(raw)
    return ValidatedPipelineConfig._from_dict(raw)


def register_config(config: ValidatedPipelineConfig) -> None:
    """Register config instance with DI container."""
    from src.core.di.container import container
    container.register_instance(ValidatedPipelineConfig, config)


# ============================================================
# Adaptive overrides (ported from loader.py)
# ============================================================

def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge *override* keys into a copy of *base*."""
    return {**base, **override}


def apply_adaptive_overrides(config: ValidatedPipelineConfig, adaptive_dict: dict[str, Any]) -> ValidatedPipelineConfig:
    """Shallow-merge adaptive-learning overrides into an existing *config*.

    For the three nested-section fields ``scoring``, ``analysis``, and
    ``nuclei`` the adaptive dict values are merged on a per-key basis
    so individual sub-settings can be adjusted without wiping the rest
    of the section.  All other fields are replaced directly.

    The original *config* object is modified **in place** and also
    returned for convenience.
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
                object.__setattr__(config, field_name, merged)
            else:
                object.__setattr__(config, field_name, value)
        elif hasattr(config, field_name):
            object.__setattr__(config, field_name, value)

    return config
