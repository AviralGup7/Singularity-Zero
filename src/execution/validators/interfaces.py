from typing import Any, Protocol, runtime_checkable

from src.core.models import ValidationResult


@runtime_checkable
class Validator(Protocol):
    def __call__(self, target: dict[str, Any], context: dict[str, Any]) -> ValidationResult: ...
