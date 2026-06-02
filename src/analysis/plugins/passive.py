from .base import AnalysisPluginSpec, spec
from .passive_registry_data import _PLUGIN_DATA

PASSIVE_PLUGIN_SPECS: tuple[AnalysisPluginSpec, ...] = tuple(
    spec(key, label, desc, group) for key, label, desc, group in _PLUGIN_DATA
)

__all__ = ["PASSIVE_PLUGIN_SPECS"]
