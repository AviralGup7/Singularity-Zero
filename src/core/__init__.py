from typing import Any


def __getattr__(name: str) -> Any:
    if name in (
        "CheckpointManager",
        "CheckpointState",
        "StageCheckpointGuard",
        "attempt_recovery",
        "create_checkpoint_manager",
        "generate_run_id",
    ):
        from src.core.checkpoint import (
            CheckpointManager,
            CheckpointState,
            StageCheckpointGuard,
            attempt_recovery,
            create_checkpoint_manager,
            generate_run_id,
        )

        return locals()[name]
    if name == "ScopeViolationError":
        from src.core.exceptions import ScopeViolationError

        return ScopeViolationError
    if name in (
        "OutboundRequestInterceptor",
        "SensitiveScopePolicy",
        "ScopeCheckResult",
        "ScopeValidator",
        "create_scope_guard",
        "validate_url_scope",
    ):
        from src.core.middleware import (
            OutboundRequestInterceptor,
            ScopeCheckResult,
            ScopeValidator,
            SensitiveScopePolicy,
            create_scope_guard,
            validate_url_scope,
        )

        return locals()[name]
    if name in ("Config", "Finding", "Request", "Response", "ValidationResult"):
        from src.core.models import Config, Finding, Request, Response, ValidationResult

        return locals()[name]
    if name in ("Session", "SessionRegistry"):
        from src.core.session import Session, SessionRegistry

        return locals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "CheckpointManager",
    "CheckpointState",
    "Config",
    "Finding",
    "OutboundRequestInterceptor",
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
