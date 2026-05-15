"""Validation engine for executing blackbox security tests.

This package modularizes the validation engine into separate files
for better maintainability and AI-agent editability.
"""

# Schema version constants
from src.core.contracts.pipeline import (
    VALIDATION_RESULT_SCHEMA_VERSION as SHARED_SCHEMA_VERSION,
)
from src.core.contracts.pipeline import (
    VALIDATION_RUNTIME_SCHEMA_VERSION as RUNTIME_SCHEMA_VERSION,
)

# Re-export helper functions from engine_helpers for backward compatibility
from src.execution.validators.engine_helpers import (
    build_token_replay_summary,
    collect_scope_hosts,
    compare_response_shapes,
    mutate_identifier,
    scope_check,
    selector_params,
)

from ._base import BaseValidator, ValidationContext
from ._http_client import ValidationHttpClient, ValidationHttpConfig
from ._runner import build_validator_registry, run_blackbox_validation_engine
from ._validators import (
    CsrfValidator,
    FileUploadValidator,
    IdorValidator,
    RedirectValidator,
    SsrfValidator,
    SstiValidator,
    TokenReuseValidator,
    XssValidator,
)

__all__ = [
    "ValidationHttpConfig",
    "ValidationHttpClient",
    "ValidationContext",
    "BaseValidator",
    "RedirectValidator",
    "SsrfValidator",
    "TokenReuseValidator",
    "IdorValidator",
    "CsrfValidator",
    "XssValidator",
    "SstiValidator",
    "FileUploadValidator",
    "build_validator_registry",
    "run_blackbox_validation_engine",
    "build_token_replay_summary",
    "collect_scope_hosts",
    "compare_response_shapes",
    "mutate_identifier",
    "scope_check",
    "selector_params",
    "SHARED_SCHEMA_VERSION",
    "RUNTIME_SCHEMA_VERSION",
]
