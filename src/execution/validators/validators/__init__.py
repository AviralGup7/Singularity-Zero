import logging
from typing import Any

from src.core.models import ValidationResult
from src.execution.validators.interfaces import Validator
from src.execution.validators.registry import VALIDATOR_ORDER
from src.execution.validators.validators.csrf import validate as validate_csrf
from src.execution.validators.validators.file_upload import validate as validate_file_upload
from src.execution.validators.validators.idor import validate as validate_idor
from src.execution.validators.validators.redirect import validate as validate_redirect
from src.execution.validators.validators.ssrf import validate as validate_ssrf
from src.execution.validators.validators.ssti import validate as validate_ssti
from src.execution.validators.validators.token_reuse import validate as validate_token_reuse
from src.execution.validators.validators.xss import validate as validate_xss

logger = logging.getLogger(__name__)

_RUNNERS: dict[str, Validator] = {
    "redirect": validate_redirect,
    "ssrf": validate_ssrf,
    "token_reuse": validate_token_reuse,
    "idor": validate_idor,
    "csrf": validate_csrf,
    "xss": validate_xss,
    "ssti": validate_ssti,
    "file_upload": validate_file_upload,
}


# Stub validators for registered but not-yet-implemented validators
def _stub_validator(name: str) -> Validator:
    """Create a stub validator that returns a no-op result and logs a warning."""

    def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
        logger.warning(
            "Stub validator '%s' invoked on %s — this is a no-op placeholder",
            name,
            target.get("url", "<unknown-url>"),
        )
        return ValidationResult(
            validator=name,
            category=name,
            url=target.get("url", ""),
            status="skipped",
            confidence=0.0,
            in_scope=True,
            scope_reason=f"{name} validator not yet implemented",
        )

    return validate


# Register stubs for unimplemented validators
for _validator_name in VALIDATOR_ORDER:
    if _validator_name not in _RUNNERS:
        _RUNNERS[_validator_name] = _stub_validator(_validator_name)

VALIDATOR_REGISTRY: dict[str, Validator] = {name: _RUNNERS[name] for name in VALIDATOR_ORDER}

__all__ = [
    "VALIDATOR_REGISTRY",
    "validate_idor",
    "validate_redirect",
    "validate_ssrf",
    "validate_token_reuse",
    "validate_csrf",
    "validate_xss",
    "validate_ssti",
    "validate_file_upload",
]
