"""Decision engine and attack selection contracts."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class DecisionEngineProtocol(Protocol):
    """Contract for finding classification, annotation, and filtering."""

    def classify_finding(
        self,
        finding: dict[str, Any],
        target_profile: dict[str, Any] | None = None,
        dynamic_fp_patterns: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]: ...

    def annotate_finding_decisions(
        self,
        findings: list[dict[str, Any]],
        target_profile: dict[str, Any] | None = None,
        dynamic_fp_patterns: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]: ...

    def filter_reportable_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]: ...


@runtime_checkable
class AttackSelectorProtocol(Protocol):
    """Contract for selecting validation actions and compound attack plans."""

    def select_validation_actions(
        self,
        *,
        url: str,
        params: list[str] | set[str] | tuple[str, ...] | None,
        signals: list[str] | set[str] | tuple[str, ...] | None,
        scope_hosts: set[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]: ...

    def select_validation_attack_plans(
        self,
        *,
        url: str,
        params: list[str] | set[str] | tuple[str, ...] | None,
        signals: list[str] | set[str] | tuple[str, ...] | None,
        scope_hosts: set[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> tuple[Any, ...]: ...


__all__ = [
    "AttackSelectorProtocol",
    "DecisionEngineProtocol",
]
