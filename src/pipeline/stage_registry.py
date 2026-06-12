"""Stage Registry for Plugin-Driven Graph Composition.

This module provides a registration API that allows plugins to declare
new pipeline stages without modifying core graph-building code.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.pipeline.services.pipeline_orchestrator._graph_dsl import StageNode, Condition

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StageNodeDefinition:
    name: str
    needs: list[str] = field(default_factory=list)
    weight: int = 1
    timeout_seconds: int = 300
    critical: bool = False
    when: Condition | None = None
    runner_name: str = ""
    produces: list[str] = field(default_factory=list)
    group: str = ""


@dataclass
class StageRegistry:
    _definitions: dict[str, StageNodeDefinition] = field(default_factory=dict)

    def register(self, defn: StageNodeDefinition) -> None:
        if defn.name in self._definitions:
            logger.warning("Stage '%s' already registered, overwriting", defn.name)
        self._definitions[defn.name] = defn

    def unregister(self, name: str) -> None:
        if name not in self._definitions:
            raise KeyError(f"Stage '{name}' is not registered")
        del self._definitions[name]

    def get_all(self) -> list[StageNodeDefinition]:
        return list(self._definitions.values())

    def get_by_group(self, group: str) -> list[StageNodeDefinition]:
        return [d for d in self._definitions.values() if d.group == group]

    def get_by_capability(self, capability: str) -> list[StageNodeDefinition]:
        result = []
        for defn in self._definitions.values():
            if defn.when is not None and _condition_references_capability(defn.when, capability):
                result.append(defn)
        return result


def _condition_references_capability(condition: Condition | None, capability: str) -> bool:
    if condition is None:
        return False
    type_name = type(condition).__name__
    if type_name == "FlagSet":
        return getattr(condition, "flag", None) == capability
    if type_name in ("All", "AnyOf"):
        return any(
            _condition_references_capability(c, capability)
            for c in getattr(condition, "conditions", [])
        )
    if type_name == "Not":
        return _condition_references_capability(getattr(condition, "condition", None), capability)
    return False


_global_stage_registry: StageRegistry = StageRegistry()


def register(defn: StageNodeDefinition) -> None:
    _global_stage_registry.register(defn)


def unregister(name: str) -> None:
    _global_stage_registry.unregister(name)


def get_all() -> list[StageNodeDefinition]:
    return _global_stage_registry.get_all()


def get_by_group(group: str) -> list[StageNodeDefinition]:
    return _global_stage_registry.get_by_group(group)


def get_by_capability(capability: str) -> list[StageNodeDefinition]:
    return _global_stage_registry.get_by_capability(capability)


def _make_stage_node(defn: StageNodeDefinition) -> StageNode:
    from src.pipeline.services.pipeline_orchestrator._graph_dsl import StageNode, AlwaysTrue

    return StageNode(
        name=defn.name,
        needs=tuple(defn.needs),
        weight=defn.weight,
        timeout=defn.timeout_seconds,
        critical=defn.critical,
        when=defn.when if defn.when is not None else AlwaysTrue(),
    )


def _register_builtin_stages() -> None:
    from src.pipeline.services.pipeline_orchestrator._graph_dsl import (
        AlwaysTrue,
        AnyOf,
        OutputNonEmpty,
        StageCompleted,
    )

    register(
        StageNodeDefinition(
            name="sca_scan",
            needs=[],
            weight=5,
            timeout_seconds=600,
            when=OutputNonEmpty("source_code_paths"),
            runner_name="sca_scan",
            produces=["sca_findings", "dependency_tree", "sbom_fragment"],
            group="scanner",
        )
    )
    register(
        StageNodeDefinition(
            name="container_scan",
            needs=[],
            weight=5,
            timeout_seconds=900,
            when=AnyOf(
                conditions=(OutputNonEmpty("container_images"), OutputNonEmpty("dockerfiles"))
            ),
            runner_name="sca_scan",
            produces=["container_findings", "image_vulns", "sbom_fragment"],
            group="scanner",
        )
    )
    register(
        StageNodeDefinition(
            name="iac_scan",
            needs=[],
            weight=5,
            timeout_seconds=600,
            when=OutputNonEmpty("iac_paths"),
            runner_name="sca_scan",
            produces=["iac_findings", "misconfigurations"],
            group="scanner",
        )
    )
    register(
        StageNodeDefinition(
            name="sbom_generate",
            needs=[],
            weight=3,
            timeout_seconds=120,
            when=AnyOf(conditions=(StageCompleted("sca_scan"), StageCompleted("container_scan"))),
            runner_name="sca_scan",
            produces=["sbom", "sbom_cyclonedx", "sbom_spdx"],
            group="scanner",
        )
    )
    register(
        StageNodeDefinition(
            name="sbom_diff",
            needs=[],
            weight=2,
            timeout_seconds=120,
            when=OutputNonEmpty("previous_sbom"),
            runner_name="sca_scan",
            produces=["sbom_diff", "new_components", "removed_components", "changed_components"],
            group="scanner",
        )
    )
    register(
        StageNodeDefinition(
            name="git_secret_scan",
            needs=[],
            weight=3,
            timeout_seconds=600,
            when=AlwaysTrue(),
            runner_name="sca_scan",
            produces=["secret_findings", "exposed_credentials_count"],
            group="scanner",
        )
    )
    register(
        StageNodeDefinition(
            name="ci_export",
            needs=["reporting"],
            weight=1,
            timeout_seconds=120,
            when=AlwaysTrue(),
            runner_name="ci_export",
            produces=["junit_xml", "github_summary", "ci_artifacts", "exit_code_recommendation"],
            group="exporter",
        )
    )
    register(
        StageNodeDefinition(
            name="scope_stage",
            needs=["urls"],
            weight=1,
            timeout_seconds=120,
            when=OutputNonEmpty("target_urls"),
            runner_name="scope_stage",
            produces=["in_scope_urls", "out_of_scope_urls", "scope_metadata"],
            group="bug_bounty",
        )
    )
    register(
        StageNodeDefinition(
            name="dedup_stage",
            needs=["reporting"],
            weight=1,
            timeout_seconds=120,
            when=AlwaysTrue(),
            runner_name="dedup_stage",
            produces=["new_findings", "duplicate_findings"],
            group="bug_bounty",
        )
    )


def list_registered_stage_definitions() -> list[StageNodeDefinition]:
    return _global_stage_registry.get_all()


def resolve_stage_definition(name: str) -> StageNodeDefinition | None:
    for defn in _global_stage_registry.get_all():
        if defn.name == name:
            return defn
    return None
