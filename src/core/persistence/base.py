from __future__ import annotations

import abc
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import uuid4

from src.core.di.container import container

T = TypeVar("T")


class QueryBuilder(abc.ABC):
    """Abstract query builder for type-safe queries."""

    @abc.abstractmethod
    async def find(self, filters: dict[str, Any] = None, limit: int = 100, offset: int = 0) -> list[Any]:
        ...

    @abc.abstractmethod
    async def find_one(self, filters: dict[str, Any]) -> Any | None:
        ...

    @abc.abstractmethod
    async def insert(self, data: dict[str, Any]) -> str:
        ...

    @abc.abstractmethod
    async def update(self, id: str, data: dict[str, Any]) -> bool:
        ...

    @abc.abstractmethod
    async def delete(self, id: str) -> bool:
        ...

    @abc.abstractmethod
    async def count(self, filters: dict[str, Any] = None) -> int:
        ...


@dataclass
class Repository(abc.ABC, Generic[T]):
    """Base repository with common CRUD operations."""

    @abc.abstractmethod
    async def create(self, entity: T) -> T:
        ...

    @abc.abstractmethod
    async def get(self, id: str) -> T | None:
        ...

    @abc.abstractmethod
    async def update(self, entity: T) -> T:
        ...

    @abc.abstractmethod
    async def delete(self, id: str) -> bool:
        ...

    @abc.abstractmethod
    async def list(self, filters: dict = None, limit: int = 100, offset: int = 0) -> list[T]:
        ...

    @abc.abstractmethod
    async def count(self, filters: dict = None) -> int:
        ...


@dataclass
class UnitOfWork(abc.ABC):
    """Unit of work pattern for transactional boundaries."""

    @abc.abstractmethod
    async def commit(self) -> None:
        ...

    @abc.abstractmethod
    async def rollback(self) -> None:
        ...

    @abc.abstractmethod
    async def __aenter__(self) -> UnitOfWork:
        ...

    @abc.abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        ...

    @property
    @abc.abstractmethod
    def repositories(self) -> dict[str, Any]:
        ...


@dataclass
class TransactionManager:
    """Manages database transactions with automatic rollback on exception."""

    def __init__(self, uow_factory: Callable[[], UnitOfWork]):
        self._uow_factory = uow_factory
        self._current_uow: UnitOfWork | None = None

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[UnitOfWork]:
        uow = self._uow_factory()
        self._current_uow = uow
        try:
            async with uow:
                yield uow
                await uow.commit()
        except Exception:
            await uow.rollback()
            raise
        finally:
            self._current_uow = None

    def get_current(self) -> UnitOfWork | None:
        return self._current_uow


# --- Base model with common fields ---

@dataclass
class BaseModel:
    id: str = field(default_factory=lambda: uuid4().hex)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaseModel:
        return cls(
            id=data.get("id", uuid4().hex),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
            version=data.get("version", 1),
        )


# --- Pagination ---

@dataclass
class Page:
    items: list[Any]
    total: int
    page: int
    size: int
    total_pages: int = field(init=False)

    def __post_init__(self):
        self.total_pages = (self.total + self.size - 1) // self.size

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": self.items,
            "total": self.total,
            "page": self.page,
            "size": self.size,
            "total_pages": self.total_pages,
        }


@dataclass
class PaginationParams:
    page: int = 1
    size: int = 20
    sort_by: str | None = None
    sort_order: str = "asc"  # asc, desc

    def __post_init__(self):
        self.page = max(1, self.page)
        self.size = max(1, min(100, self.size))

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.size


# --- Soft delete support ---

@dataclass
class SoftDeleteMixin:
    deleted_at: datetime | None = None
    deleted_by: str | None = None

    def soft_delete(self, deleted_by: str = "system") -> None:
        self.deleted_at = datetime.now()
        self.deleted_by = deleted_by

    def restore(self) -> None:
        self.deleted_at = None
        self.deleted_by = None

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


# --- Optimistic locking ---

@dataclass
class OptimisticLockMixin:
    version: int = 1

    def check_version(self, expected_version: int) -> bool:
        return self.version == expected_version

    def increment_version(self) -> None:
        self.version += 1


# --- Filter and sort utilities ---

@dataclass
class Filter:
    field: str
    operator: str  # eq, ne, gt, gte, lt, lte, like, in, not_in, is_null, is_not_null
    value: Any

    def apply(self, query: Any) -> Any:
        """Apply filter to query. Override in backend-specific implementation."""
        return query


@dataclass
class Sort:
    field: str
    order: str = "asc"  # asc, desc


@dataclass
class QueryOptions:
    filters: list[Filter] = field(default_factory=list)
    sorts: list[Sort] = field(default_factory=list)
    pagination: PaginationParams = field(default_factory=PaginationParams)


# --- Result types ---

@dataclass
class Result(Generic[T]):
    """Result wrapper with success/error handling."""
    success: bool
    data: T | None = None
    error: str | None = None
    error_code: str | None = None

    @classmethod
    def ok(cls, data: T) -> Result[T]:
        return cls(success=True, data=data)

    @classmethod
    def err(cls, error: str, code: str = None) -> Result[T]:
        return cls(success=False, error=error, error_code=code)

    def unwrap(self) -> T:
        if not self.success:
            raise ValueError(f"Result error: {self.error}")
        return self.data

    def unwrap_or(self, default: T) -> T:
        return self.data if self.success else default


async def transactional(func: Callable[..., T]) -> Callable[..., T]:
    """Decorator for automatic transaction management."""
    from functools import wraps

    @wraps(func)
    async def wrapper(*args, **kwargs) -> T:
        tx_manager = container.resolve(TransactionManager)
        # The unit of work is entered for its side effects (begin/commit or
        # rollback); the wrapped function reaches it through the container,
        # so the handle itself is deliberately not bound to a name.
        async with tx_manager.transaction():
            return await func(*args, **kwargs)

    # RETURNS THE WRAPPER, NOT THE ORIGINAL. This said `return func`, which
    # made the decorator a no-op: every function decorated with it ran with
    # no transaction at all, silently. Latent today (no call sites yet), and
    # exactly the kind of thing that is discovered after it has corrupted
    # something, so it is fixed now rather than annotated.
    return wrapper


# --- Specification pattern ---

class Specification(abc.ABC, Generic[T]):
    @abc.abstractmethod
    def is_satisfied_by(self, candidate: T) -> bool:
        ...

    def and_(self, other: Specification[T]) -> Specification[T]:
        return AndSpecification(self, other)

    def or_(self, other: Specification[T]) -> Specification[T]:
        return OrSpecification(self, other)

    def not_(self) -> Specification[T]:
        return NotSpecification(self)


class AndSpecification(Specification[T]):
    def __init__(self, left: Specification[T], right: Specification[T]):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        return self.left.is_satisfied_by(candidate) and self.right.is_satisfied_by(candidate)


class OrSpecification(Specification[T]):
    def __init__(self, left: Specification[T], right: Specification[T]):
        self.left = left
        self.right = right

    def is_satisfied_by(self, candidate: T) -> bool:
        return self.left.is_satisfied_by(candidate) or self.right.is_satisfied_by(candidate)


class NotSpecification(Specification[T]):
    def __init__(self, spec: Specification[T]):
        self.spec = spec

    def is_satisfied_by(self, candidate: T) -> bool:
        return not self.spec.is_satisfied_by(candidate)
