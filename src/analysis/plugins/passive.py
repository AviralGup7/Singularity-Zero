from ._passive_constants import _PLUGIN_DATA
from .base import AnalysisPluginSpec, spec

PASSIVE_PLUGIN_SPECS: tuple[AnalysisPluginSpec, ...] = tuple(
    spec(key, label, desc, group) for key, label, desc, group in _PLUGIN_DATA
)

__all__ = ["PASSIVE_PLUGIN_SPECS"]
