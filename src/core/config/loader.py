"""Configuration loader for the security testing pipeline.

.. deprecated::
    This module is a compatibility shim. New code should use
    ``src.core.config.typed_config`` directly.

    - ``load_config`` now returns ``ValidatedPipelineConfig`` (canonical v2 model).
    - ``apply_adaptive_overrides`` now operates on ``ValidatedPipelineConfig``.
    - ``Config`` is still importable from ``src.core.models.config`` but emits
      a ``DeprecationWarning``.
"""

from __future__ import annotations

import json
import os
import re
import warnings
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline import CONFIG_DEFAULTS

warnings.warn(
    "src.core.config.loader is deprecated. "
    "Use src.core.config.typed_config for the canonical config system.",
    DeprecationWarning,
    stacklevel=2,
)

# Keep legacy Config importable for backward compatibility
from src.core.models.config import Config  # noqa: E402

# Re-export canonical implementations from typed_config
from src.core.config.typed_config import (  # noqa: E402
    ValidatedPipelineConfig,
    apply_adaptive_overrides,
    load_config,
)

# Re-export private helpers for backward compatibility with tests
from src.core.config.typed_config import (  # noqa: E402
    _interpolate_env_vars,
    _merge_dict,
    _NESTED_MERGE_FIELDS,
    _optional_mapping,
    _positive_int,
    _require_text,
    _resolve_storage_config,
    _STORAGE_ENV_BACKEND,
    _STORAGE_ENV_REDIS_URL,
    _STORAGE_ENV_S3_BUCKET,
    _STORAGE_ENV_S3_ENDPOINT,
    _STORAGE_ENV_S3_PREFIX,
    _STORAGE_ENV_S3_REGION,
)

__all__ = [
    "apply_adaptive_overrides",
    "Config",
    "load_config",
    "ValidatedPipelineConfig",
]
