from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, TypeVar, get_type_hints

T = TypeVar("T")

_current_scope: ContextVar[dict[type, Any]] = ContextVar("_current_scope", default={})
_container_lock = threading.Lock()


@dataclass
class ServiceRegistration:
    factory: Callable[..., Any]
    singleton: bool = False
    instance: Any = None
    dependencies: tuple[type, ...] = field(default_factory=tuple)


class DIContainer:
    """Thread-safe, scope-aware dependency injection container."""

    def __init__(self) -> None:
        self._services: dict[type, ServiceRegistration] = {}
        self._lock = threading.RLock()

    def register(
        self,
        interface: type[T],
        factory: Callable[..., T],
        *,
        singleton: bool = False,
    ) -> None:
        with self._lock:
            deps = tuple(get_type_hints(factory).values())
            self._services[interface] = ServiceRegistration(
                factory=factory,
                singleton=singleton,
                dependencies=deps,
            )

    def register_instance(self, interface: type[T], instance: T) -> None:
        with self._lock:
            self._services[interface] = ServiceRegistration(
                factory=lambda: instance,
                singleton=True,
                instance=instance,
            )

    def resolve(self, interface: type[T]) -> T:
        scope = _current_scope.get()
        if interface in scope:
            return scope[interface]

        with self._lock:
            reg = self._services.get(interface)
            if not reg:
                raise KeyError(f"No registration for {interface}")

            if reg.singleton and reg.instance is not None:
                return reg.instance

            kwargs = {dep: self.resolve(dep) for dep in reg.dependencies}
            instance = reg.factory(**kwargs)

            if reg.singleton:
                reg.instance = instance

            scope[interface] = instance
            return instance

    @contextmanager
    def scope(self):
        """Create a new resolution scope (e.g., per request)."""
        token = _current_scope.set({})
        try:
            yield
        finally:
            _current_scope.reset(token)


# Global container (initialized once at startup)
container = DIContainer()


def inject[T](interface: type[T]) -> T:
    """Resolve a dependency at call site."""
    return container.resolve(interface)
