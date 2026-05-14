from .dashboard import DASHBOARD_REGISTRY

ANALYSIS_CHECK_OPTIONS = DASHBOARD_REGISTRY["analysis"]["check_options"]
ANALYSIS_CONTROL_GROUPS = DASHBOARD_REGISTRY["analysis"]["control_groups"]
ANALYSIS_FOCUS_PRESETS = DASHBOARD_REGISTRY["analysis"]["focus_presets"]
MODULE_OPTIONS = DASHBOARD_REGISTRY["modules"]["options"]
MODULE_GROUPS = DASHBOARD_REGISTRY["modules"]["groups"]
MODE_PRESETS = DASHBOARD_REGISTRY["modules"]["mode_presets"]
PROGRESS_PREFIX = DASHBOARD_REGISTRY["pipeline"]["progress_prefix"]
STAGE_LABELS = DASHBOARD_REGISTRY["pipeline"]["stage_labels"]

__all__ = [
    "ANALYSIS_CHECK_OPTIONS",
    "ANALYSIS_CONTROL_GROUPS",
    "ANALYSIS_FOCUS_PRESETS",
    "DASHBOARD_REGISTRY",
    "MODE_PRESETS",
    "MODULE_GROUPS",
    "MODULE_OPTIONS",
    "PROGRESS_PREFIX",
    "STAGE_LABELS",
]
