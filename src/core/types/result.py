"""Algebraic Result monad for explicit, type-safe error handling."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

T = TypeVar("T")
E = TypeVar("E")
U = TypeVar("U")
F = TypeVar("F")


@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):  # noqa: UP046
    """Successful result container."""

    value: T

    def is_ok(self) -> bool:
        return True

    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T:
        return self.value

    def unwrap_or(self, default: Any) -> T:
        return self.value

    def unwrap_err(self) -> Any:
        raise ValueError(f"Called unwrap_err on Ok value: {self.value}")

    def map(self, fn: Callable[[T], U]) -> Result[U, Any]:
        return Ok(fn(self.value))

    def map_err(self, fn: Callable[[Any], Any]) -> Result[T, Any]:
        return self

    def and_then(self, fn: Callable[[T], Result[U, E]]) -> Result[U, E]:
        return fn(self.value)


@dataclass(frozen=True, slots=True)
class Err(Generic[E]):  # noqa: UP046
    """Failure result container."""

    error: E

    def is_ok(self) -> bool:
        return False

    def is_err(self) -> bool:
        return True

    def unwrap(self) -> Any:
        raise ValueError(f"Called unwrap on Err value: {self.error}")

    def unwrap_or(self, default: U) -> U:
        return default

    def unwrap_err(self) -> E:
        return self.error

    def map(self, fn: Callable[[Any], Any]) -> Result[Any, E]:
        return self

    def map_err(self, fn: Callable[[E], F]) -> Result[Any, F]:
        return Err(fn(self.error))

    def and_then(self, fn: Callable[[Any], Any]) -> Result[Any, E]:
        return self


Result = Ok[T] | Err[E]

__all__ = [
    "Err",
    "Ok",
    "Result",
]
