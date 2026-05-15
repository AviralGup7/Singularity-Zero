"""Capability interfaces for external tool integrations.

Defines strict Protocol classes that external providers (plugins) must
adhere to, ensuring loose coupling and type-safe orchestration.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from src.core.contracts.pipeline_runtime import StageInput, StageOutput


@runtime_checkable
class SubdomainEnumeratorProtocol(Protocol):
    """Interface for passive or active subdomain discovery."""

    def __call__(
        self,
        domain: str,
        *,
        timeout_seconds: int = 120,
        retry_policy: Any | None = None,
    ) -> set[str]: ...


@runtime_checkable
class UrlCollectorProtocol(Protocol):
    """Interface for historical or live URL discovery."""

    def __call__(
        self,
        target_hosts: list[str],
        *,
        timeout_seconds: int = 120,
        retry_policy: Any | None = None,
        progress_callback: Any | None = None,
    ) -> set[str]: ...


@runtime_checkable
class LiveHostProberProtocol(Protocol):
    """Interface for verifying HTTP availability of subdomains."""

    def __call__(
        self,
        subdomains: set[str],
        *,
        timeout_seconds: int = 120,
        force_recheck: bool = False,
    ) -> tuple[list[dict[str, Any]], set[str]]: ...


@runtime_checkable
class VulnerabilityScannerProtocol(Protocol):
    """Interface for active or passive vulnerability scanning."""

    async def __call__(
        self,
        stage_input: StageInput,
    ) -> StageOutput: ...


@runtime_checkable
class EnrichmentProviderProtocol(Protocol):
    """Interface for adding intelligence to discovered findings."""

    async def __call__(
        self,
        findings: list[dict[str, Any]],
        context: Mapping[str, Any],
    ) -> list[dict[str, Any]]: ...
