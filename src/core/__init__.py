"""Core package — foundational contracts, models, config, checkpoint, session, and utilities.

Must not depend on any other ``src`` module (analysis, pipeline, dashboard,
infrastructure, execution, fuzzing).  Enforced by ``.import-linter`` contract 4.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description — published for registry, dashboard, audit log
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "core",
    "version": "3.1.0",
    "description": (
        "Foundational contracts, models, config, checkpoint, session, and "
        "utility layer. No dependency on any other src module."
    ),
    "layer": "core",
    "submodules": (
        "checkpoint",
        "config",
        "contracts",
        "frontier",
        "health",
        "middleware",
        "models",
        "parsers",
        "plugins",
        "utils",
    ),
    "public_api": (
        "PipelineConfig",
        "Finding",
        "Request",
        "Response",
        "Session",
        "ScopeValidator",
        "CheckpointManager",
        "generate_run_id",
    ),
    "depends_on": (),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify core subsystem health.

    Checks:
    - Plugin registry is instantiated and accessible.
    - Core config loader is importable.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"error"``), ``module``,
        ``version``, and optional ``details`` / ``errors``.
    """
    try:
        from src.core.config.typed_config import load_config  # noqa: F401
        from src.core.plugins.registry import GLOBAL_PLUGIN_REGISTRY  # noqa: F401

        return {
            "status": "ok",
            "module": "core",
            "version": "3.1.0",
            "details": {
                "plugin_registry": "available",
                "config_loader": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "error",
            "module": "core",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

# ---------------------------------------------------------------------------
# Public API re-exports (unchanged)
# ---------------------------------------------------------------------------

from src.core.checkpoint import (
    CheckpointManager,
    CheckpointState,
    StageCheckpointGuard,
    attempt_recovery,
    create_checkpoint_manager,
    generate_run_id,
)
from src.core.exceptions import ScopeViolationError
from src.core.middleware import (
    OutboundRequestInterceptor,
    ScopeCheckResult,
    ScopeValidator,
    SensitiveScopePolicy,
    create_scope_guard,
    validate_url_scope,
)
from src.core.models import Finding, Request, Response, ValidationResult
from src.core.config.typed_config import PipelineConfig
from src.core.session import Session, SessionRegistry

__all__ = [
    "CheckpointManager",
    "CheckpointState",
    "Finding",
    "OutboundRequestInterceptor",
    "PipelineConfig",
    "Request",
    "Response",
    "SensitiveScopePolicy",
    "ScopeCheckResult",
    "ScopeValidator",
    "ScopeViolationError",
    "Session",
    "SessionRegistry",
    "StageCheckpointGuard",
    "ValidationResult",
    "attempt_recovery",
    "create_checkpoint_manager",
    "create_scope_guard",
    "generate_run_id",
    "validate_url_scope",
]
