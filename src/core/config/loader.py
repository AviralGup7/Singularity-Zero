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

import warnings

warnings.warn(
    "src.core.config.loader is deprecated. "
    "Use src.core.config.typed_config for the canonical config system.",
    DeprecationWarning,
    stacklevel=2,
)

# Keep legacy Config importable for backward compatibility
# Re-export canonical implementations from typed_config
# Re-export private helpers for backward compatibility with tests
from src.core.config.typed_config import (  # noqa: E402
    ValidatedPipelineConfig,
    _resolve_storage_config,
    apply_adaptive_overrides,
    load_config,
)
from src.core.models.config import Config  # noqa: E402

__all__ = [
    "apply_adaptive_overrides",
    "Config",
    "load_config",
    "ValidatedPipelineConfig",
    "_resolve_storage_config",
]
