"""Validation strategy protocol and specification for pluggable validators.

Defines the ValidationStrategy Protocol that concrete validators must implement,
and ValidationStrategySpec for registering strategies with the validation engine.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ValidationStrategy(Protocol):
    """Protocol for validation strategy implementations.

    Concrete strategies must provide a name, result key, and run() method
    that returns a tuple of (results, errors) lists.
    """

    name: str
    result_key: str

    def run(self, context: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]: ...


@dataclass(frozen=True)
class ValidationStrategySpec:
    """Specification for registering a validation strategy.

    Attributes:
        name: Human-readable strategy name.
        result_key: Key used to store results in the validation output.
        strategy_factory: Callable that creates a ValidationStrategy instance.
    """

    name: str
    result_key: str
    strategy_factory: Callable[..., ValidationStrategy]
