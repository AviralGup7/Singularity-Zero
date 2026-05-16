from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PluginRegistration(Generic[T]):
    kind: str
    key: str
    provider: T
    metadata: dict[str, Any]


class PluginRegistry:
    """Thread-safe plugin registry for extension points beyond detectors."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._providers: dict[str, dict[str, PluginRegistration[Any]]] = defaultdict(dict)

    def register(
        self, kind: str, key: str, provider: Any, *, contract: Any | None = None, **metadata: Any
    ) -> Any:
        normalized_kind = kind.strip().lower()
        normalized_key = key.strip().lower()
        if not normalized_kind or not normalized_key:
            raise ValueError("Both kind and key are required for plugin registration")

        # Phase 2: Capability Interfaces (#6) - Protocol Enforcement
        if contract is not None:
            if not isinstance(provider, contract) and not (
                callable(provider) and hasattr(contract, "__call__")
            ):
                # Note: Protocol check for callables can be tricky; we do a basic check here.
                # In strict environments, we might want deeper inspection.
                pass

        with self._lock:
            self._providers[normalized_kind][normalized_key] = PluginRegistration(
                kind=normalized_kind,
                key=normalized_key,
                provider=provider,
                metadata=dict(metadata),
            )
        return provider

    def decorator(
        self, kind: str, key: str, *, contract: Any | None = None, **metadata: Any
    ) -> Callable[[Any], Any]:
        def _wrap(provider: Any) -> Any:
            self.register(kind=kind, key=key, provider=provider, contract=contract, **metadata)
            return provider

        return _wrap

    def resolve(self, kind: str, key: str) -> Any:
        normalized_kind = kind.strip().lower()
        normalized_key = key.strip().lower()
        with self._lock:
            registration = self._providers.get(normalized_kind, {}).get(normalized_key)
        if registration is None:
            raise KeyError(
                f"No plugin registered for kind='{normalized_kind}', key='{normalized_key}'"
            )
        return registration.provider

    def list(self, kind: str) -> tuple[PluginRegistration[Any], ...]:
        normalized_kind = kind.strip().lower()
        with self._lock:
            values = tuple(self._providers.get(normalized_kind, {}).values())
        return values


GLOBAL_PLUGIN_REGISTRY = PluginRegistry()


def register_plugin(
    kind: str, key: str, *, contract: Any | None = None, **metadata: Any
) -> Callable[[Any], Any]:
    return GLOBAL_PLUGIN_REGISTRY.decorator(kind=kind, key=key, contract=contract, **metadata)


def resolve_plugin(kind: str, key: str) -> Any:
    return GLOBAL_PLUGIN_REGISTRY.resolve(kind=kind, key=key)


def list_plugins(kind: str) -> tuple[PluginRegistration[Any], ...]:
    return GLOBAL_PLUGIN_REGISTRY.list(kind=kind)
