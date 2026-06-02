"""Detection plugin registry providing metadata about available analyzers.

Defines DetectionPlugin dataclass and builds the DETECTION_PLUGINS tuple
from analysis plugin specifications, adding phase, input kind, and
consumes/produces metadata from analyzer bindings.
"""

import logging
from dataclasses import dataclass
from typing import Any

from src.analysis.plugin_runtime import (
    ANALYZER_BINDING,
    ANALYZER_BINDINGS,
    AnalysisExecutionContext,
    run_registered_analyzer,
)
from src.analysis.plugins import DETECTOR_SPEC
from src.core.plugins import list_plugins

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectionPlugin:
    key: str
    label: str
    group: str
    input_kind: str
    enabled_by_default: bool
    phase: str = "discover"
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()


def _build_detection_plugins() -> tuple[DetectionPlugin, ...]:
    specs = {reg.key: reg.provider for reg in list_plugins(DETECTOR_SPEC)}
    bindings = {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}

    plugins: list[DetectionPlugin] = []
    for key, binding in bindings.items():
        spec = specs.get(key)
        label = spec.label if spec else key.replace("_", " ").title()
        group = spec.group if spec else "custom"
        enabled_by_default = spec.enabled_by_default if spec else True
        plugins.append(
            DetectionPlugin(
                key=key,
                label=label,
                group=group,
                input_kind=binding.input_kind,
                enabled_by_default=enabled_by_default,
                phase=binding.phase,
                consumes=binding.consumes,
                produces=binding.produces,
            )
        )
    return tuple(plugins)


def list_detection_plugins() -> tuple[DetectionPlugin, ...]:
    return _build_detection_plugins()


DETECTION_PLUGINS: tuple[DetectionPlugin, ...]
DETECTION_PLUGINS_BY_KEY: dict[str, DetectionPlugin]


def __getattr__(name: str) -> Any:
    if name == "DETECTION_PLUGINS":
        return list_detection_plugins()
    if name == "DETECTION_PLUGINS_BY_KEY":
        return {p.key: p for p in list_detection_plugins()}
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


_DETECTION_PLUGIN_OPTIONS: list[dict[str, Any]] | None = None


def get_detection_plugin(plugin_key: str) -> DetectionPlugin:
    normalized = plugin_key.strip()
    plugins = {p.key: p for p in list_detection_plugins()}
    plugin = plugins.get(normalized)
    if plugin is None:
        available = ", ".join(sorted(plugins.keys()))
        logger.warning(
            "Failed to resolve detection plugin key: '%s' (normalized: '%s'). Available keys: %s",
            plugin_key,
            normalized,
            available,
        )
        raise KeyError(
            f"Unknown detection plugin '{plugin_key}' (normalized: '{normalized}'). "
            f"Available plugins: {available}"
        )
    logger.debug("Successfully resolved detection plugin: %s", normalized)
    return plugin


def run_detection_plugin(
    plugin_key: str, context: AnalysisExecutionContext
) -> list[dict[str, Any]]:
    plugin = get_detection_plugin(plugin_key)
    binding = ANALYZER_BINDINGS.get(plugin.key)
    if binding is None:
        # Fallback to dynamic lookup in list_plugins
        bindings = {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}
        binding = bindings.get(plugin.key)
    if binding is None:
        raise KeyError(f"No analyzer binding found for plugin key '{plugin.key}'")
    logger.info("Running detection plugin: %s", plugin.key)
    results = run_registered_analyzer(binding, context)
    logger.info("Detection plugin %s returned %d results", plugin.key, len(results))
    return results


def detection_plugin_options() -> list[dict[str, object]]:
    global _DETECTION_PLUGIN_OPTIONS
    if _DETECTION_PLUGIN_OPTIONS is None:
        logger.info("Initializing detection plugin options cache")
        specs = {reg.key: reg.provider for reg in list_plugins(DETECTOR_SPEC)}
        _DETECTION_PLUGIN_OPTIONS = [
            {
                "name": plugin.key,
                "label": plugin.label,
                "description": specs[plugin.key].description if plugin.key in specs else "",
                "group": plugin.group,
                "input_kind": plugin.input_kind,
                "enabled_by_default": plugin.enabled_by_default,
                "phase": plugin.phase,
                "consumes": list(plugin.consumes),
                "produces": list(plugin.produces),
            }
            for plugin in list_detection_plugins()
        ]
    return [opt.copy() for opt in _DETECTION_PLUGIN_OPTIONS]
