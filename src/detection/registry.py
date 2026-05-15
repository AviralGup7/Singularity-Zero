"""Detection plugin registry providing metadata about available analyzers.

Defines DetectionPlugin dataclass and builds the DETECTION_PLUGINS tuple
from analysis plugin specifications, adding phase, input kind, and
consumes/produces metadata from analyzer bindings.
"""

from dataclasses import dataclass
from typing import Any

from src.analysis.plugin_runtime import (
    ANALYZER_BINDING,
    AnalysisExecutionContext,
    run_registered_analyzer,
)
from src.analysis.plugins import DETECTOR_SPEC
from src.core.plugins import list_plugins


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
    for key, spec in specs.items():
        binding = bindings.get(key)
        if binding is None:
            continue
        plugins.append(
            DetectionPlugin(
                key=key,
                label=spec.label,
                group=spec.group,
                input_kind=binding.input_kind,
                enabled_by_default=spec.enabled_by_default,
                phase=binding.phase,
                consumes=binding.consumes,
                produces=binding.produces,
            )
        )
    return tuple(plugins)


def list_detection_plugins() -> tuple[DetectionPlugin, ...]:
    return _build_detection_plugins()


DETECTION_PLUGINS = _build_detection_plugins()
DETECTION_PLUGINS_BY_KEY = {p.key: p for p in DETECTION_PLUGINS}


def get_detection_plugin(plugin_key: str) -> DetectionPlugin:
    normalized = plugin_key.strip()
    plugins = {p.key: p for p in list_detection_plugins()}
    plugin = plugins.get(normalized)
    if plugin is None:
        available = ", ".join(sorted(plugins))
        raise KeyError(f"Unknown detection plugin '{plugin_key}'. Available plugins: {available}")
    return plugin


def run_detection_plugin(
    plugin_key: str, context: AnalysisExecutionContext
) -> list[dict[str, Any]]:
    plugin = get_detection_plugin(plugin_key)
    from src.analysis.plugin_runtime import ANALYZER_BINDINGS

    binding = ANALYZER_BINDINGS[plugin.key]
    return run_registered_analyzer(binding, context)


def detection_plugin_options() -> list[dict[str, object]]:
    specs = {reg.key: reg.provider for reg in list_plugins(DETECTOR_SPEC)}
    return [
        {
            "name": plugin.key,
            "label": plugin.label,
            "description": specs[plugin.key].description,
            "group": plugin.group,
            "input_kind": plugin.input_kind,
            "enabled_by_default": plugin.enabled_by_default,
            "phase": plugin.phase,
            "consumes": list(plugin.consumes),
            "produces": list(plugin.produces),
        }
        for plugin in list_detection_plugins()
    ]
