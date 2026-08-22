from __future__ import annotations

import json
import os
import re
import types
from dataclasses import MISSING, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union, get_args, get_origin, get_type_hints

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


def _union_args(target_type: Any) -> tuple[Any, ...] | None:
    origin = get_origin(target_type)
    if origin is Union or origin is getattr(types, "UnionType", None):
        return get_args(target_type)
    return None


def _is_nested_config_type(target_type: Any) -> bool:
    return (
        isinstance(target_type, type)
        and is_dataclass(target_type)
        and callable(getattr(target_type, "_from_dict", None))
    )


def _coerce_value(value: Any, target_type: Any) -> Any:
    """Coerce value to target type, including nested TypedConfig sections."""
    if value is None or target_type is Any:
        return value

    union_args = _union_args(target_type)
    if union_args is not None:
        last_error: Exception | None = None
        for alt in union_args:
            if alt is type(None):
                continue
            try:
                return _coerce_value(value, alt)
            except (TypeError, ValueError) as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        return value

    if _is_nested_config_type(target_type):
        if isinstance(value, target_type):
            return value
        if isinstance(value, dict):
            return target_type._from_dict(value)
        raise ValueError(
            f"Expected mapping for {getattr(target_type, '__name__', target_type)}, "
            f"got {type(value).__name__}"
        )

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
        if len(args) != 2:
            return dict(value)
        key_type, val_type = args
        if val_type is Any or val_type is dict:
            return {
                _coerce_value(k, key_type): dict(v) if isinstance(v, dict) else v
                for k, v in value.items()
            }
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

    def __post_init__(self) -> None:
        if not hasattr(self, "_extra"):
            object.__setattr__(self, "_extra", {})

    @classmethod
    def load(cls, path: Path | str) -> TypedConfig:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> TypedConfig:
        if not isinstance(data, dict):
            raise ValueError(f"Expected mapping for {cls.__name__}, got {type(data).__name__}")
        kwargs: dict[str, Any] = {}
        extras: dict[str, Any] = {}
        hints = get_type_hints(cls)
        known = {f.name for f in fields(cls)}

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

        for key, value in data.items():
            if key not in known:
                extras[key] = value

        obj = cls(**kwargs)
        object.__setattr__(obj, "_extra", extras)
        return obj

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-compatible lookup used by pipeline/recon consumers."""
        names = {f.name for f in fields(self)}
        if key in names:
            return getattr(self, key)
        return getattr(self, "_extra", {}).get(key, default)

    def __getitem__(self, key: str) -> Any:
        names = {f.name for f in fields(self)}
        if key in names:
            return getattr(self, key)
        extra = getattr(self, "_extra", {})
        if key in extra:
            return extra[key]
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        if key in {f.name for f in fields(self)}:
            return True
        return key in getattr(self, "_extra", {})

    def to_dict(self) -> dict:
        payload: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, TypedConfig):
                payload[f.name] = value.to_dict()
            else:
                payload[f.name] = value
        payload.update(getattr(self, "_extra", {}))
        return payload

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
    weights: dict[str, int] = field(
        default_factory=lambda: {
            "api": 3,
            "auth": 4,
            "redirect": 3,
            "param": 2,
            "sensitive": 5,
            "idor": 4,
            "ssrf": 5,
            "xss": 4,
            "sqli": 5,
        }
    )
    custom_keyword_bonus: int = 2
    contexts: dict[str, dict] = field(
        default_factory=lambda: {
            "api_heavy": {"bonus": 3, "keywords": ["/api/", "/v1/", "/v2/", "graphql"]},
            "auth_heavy": {
                "bonus": 4,
                "keywords": ["/auth", "/login", "/oauth", "token", "session"],
            },
            "file_heavy": {"bonus": 3, "keywords": ["upload", "download", "file", "export"]},
        }
    )
    modes: dict[str, dict] = field(
        default_factory=lambda: {
            "full": {
                "param_bonus": 2,
                "parameter_keywords": ["id", "user", "account"],
                "path_keywords": ["/api/", "/admin/"],
            },
            "idor": {
                "param_bonus": 5,
                "parameter_keywords": ["id", "user_id", "account_id"],
                "path_keywords": [],
            },
            "ssrf": {
                "param_bonus": 5,
                "parameter_keywords": ["url", "uri", "dest", "redirect"],
                "path_keywords": [],
            },
        }
    )


@dataclass
class FilterConfig(TypedConfig):
    ignore_extensions: list[str] = field(
        default_factory=lambda: [
            "css",
            "js",
            "png",
            "jpg",
            "jpeg",
            "gif",
            "svg",
            "woff",
            "woff2",
            "ttf",
            "eot",
            "ico",
            "pdf",
            "zip",
            "gz",
            "tar",
            "rar",
            "7z",
            "mp4",
            "webm",
            "mp3",
            "wav",
            "ogg",
            "flac",
            "avi",
            "mov",
        ]
    )
    priority_keywords: list[str] = field(
        default_factory=lambda: [
            "admin",
            "api",
            "auth",
            "login",
            "oauth",
            "token",
            "session",
            "password",
            "reset",
            "register",
            "signup",
            "register",
        ]
    )
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


def _merge_into_typed(current: TypedConfig, override: dict[str, Any]) -> None:
    """Merge override keys into a TypedConfig instance without replacing it."""
    hints = get_type_hints(type(current))
    known = {f.name for f in fields(current)}
    extra = dict(getattr(current, "_extra", {}))
    for key, value in override.items():
        if key in known:
            existing = getattr(current, key)
            if isinstance(existing, TypedConfig) and isinstance(value, dict):
                _merge_into_typed(existing, value)
            elif isinstance(existing, dict) and isinstance(value, dict):
                object.__setattr__(current, key, _merge_dict(existing, value))
            else:
                object.__setattr__(current, key, _coerce_value(value, hints.get(key, Any)))
        elif isinstance(extra.get(key), dict) and isinstance(value, dict):
            extra[key] = _merge_dict(extra[key], value)
        else:
            extra[key] = value
    object.__setattr__(current, "_extra", extra)


def apply_adaptive_overrides(
    config: ValidatedPipelineConfig, adaptive_dict: dict[str, Any]
) -> ValidatedPipelineConfig:
    """Shallow-merge adaptive-learning overrides into an existing *config*.

    Nested ``TypedConfig`` sections (cache/httpx/nuclei/scoring/filters)
    keep their type: known fields are updated in place and unknown keys
    are stored on ``_extra`` so ``.get()`` still works. Dict sections
    listed in ``_NESTED_MERGE_FIELDS`` (and legacy ``Config`` dict
    sections) are shallow-merged. All other fields are replaced directly.

    The original *config* object is modified **in place** and also
    returned for convenience.
    """
    if not adaptive_dict:
        return config

    for field_name, value in adaptive_dict.items():
        current = getattr(config, field_name, None) if hasattr(config, field_name) else None
        if isinstance(current, TypedConfig) and isinstance(value, dict):
            _merge_into_typed(current, value)
            continue
        if field_name in _NESTED_MERGE_FIELDS:
            if not isinstance(current, dict):
                current = {}
            if isinstance(value, dict):
                object.__setattr__(config, field_name, _merge_dict(current, value))
            else:
                object.__setattr__(config, field_name, value)
        elif hasattr(config, field_name):
            object.__setattr__(config, field_name, value)

    return config
