from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisPluginSpec:
    key: str
    label: str
    description: str
    group: str
    slug: str
    enabled_by_default: bool = True


_SLUG_OVERRIDES = {
    "behavior_analysis_layer": "behavior_analysis",
    "response_snapshot_system": "response_snapshots",
    "smart_payload_suggestions": "payload_suggestions",
}


def _default_slug(key: str) -> str:
    if key in _SLUG_OVERRIDES:
        return _SLUG_OVERRIDES[key]
    for suffix in ("_checker", "_detector", "_analyzer"):
        if key.endswith(suffix):
            return key[: -len(suffix)]
    return key


def spec(
    key: str,
    label: str,
    description: str,
    group: str,
    *,
    slug: str | None = None,
    enabled_by_default: bool = True,
) -> AnalysisPluginSpec:
    return AnalysisPluginSpec(
        key=key,
        label=label,
        description=description,
        group=group,
        slug=slug or _default_slug(key),
        enabled_by_default=enabled_by_default,
    )


_spec = spec
_plugin_data = spec
