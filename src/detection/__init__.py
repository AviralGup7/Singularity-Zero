from importlib import import_module
from typing import Any


def __getattr__(name: str) -> Any:
    if name in {
        "DETECTION_PLUGINS",
        "DETECTION_PLUGINS_BY_KEY",
        "DetectionPlugin",
        "detection_plugin_options",
        "get_detection_plugin",
        "list_detection_plugins",
        "run_detection_plugin",
        "registry",
    }:
        module = import_module("src.detection.registry")
        if name == "registry":
            return module
        return getattr(module, name)
    if name in {"prime_detection_context", "run_detection_plugins", "runtime"}:
        module = import_module("src.detection.runtime")
        if name == "runtime":
            return module
        return getattr(module, name)
    if name in {"compose_signals", "signals"}:
        module = import_module("src.detection.signals")
        if name == "signals":
            return module
        return getattr(module, name)
    raise AttributeError(name)


__all__ = [
    "DETECTION_PLUGINS",
    "DETECTION_PLUGINS_BY_KEY",
    "DetectionPlugin",
    "detection_plugin_options",
    "get_detection_plugin",
    "list_detection_plugins",
    "prime_detection_context",
    "run_detection_plugins",
    "compose_signals",
    "run_detection_plugin",
]
