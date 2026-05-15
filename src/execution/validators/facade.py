"""Validation facade providing simplified access to the validator registry.

Offers validate_target() and validate_many() functions for running individual
or batch validations against targets using named validators.
"""

from typing import Any

from src.core.models import ValidationResult
from src.execution.validators.validators import VALIDATOR_REGISTRY


def validate_target(
    target: dict[str, Any], context: dict[str, Any], *, validator_name: str
) -> ValidationResult:
    """Run a single validation against a target using a named validator.

    Args:
        target: Target dict with URL and metadata.
        context: Validation context dict.
        validator_name: Name of the validator to use.

    Returns:
        ValidationResult with status, confidence, and evidence.

    Raises:
        ValueError: If the validator name is not registered.
    """
    validator = VALIDATOR_REGISTRY.get(validator_name)
    if validator is None:
        raise ValueError(f"Unknown validator: {validator_name}")
    return validator(target, context)


def validate_many(
    targets: list[dict[str, Any]], context: dict[str, Any], *, validator_name: str
) -> list[ValidationResult]:
    """Run validations against multiple targets using a named validator.

    Args:
        targets: List of target dicts.
        context: Validation context dict.
        validator_name: Name of the validator to use.

    Returns:
        List of ValidationResult objects, one per target.
    """
    return [validate_target(target, context, validator_name=validator_name) for target in targets]
