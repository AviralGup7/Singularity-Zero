def __getattr__(name: str):
    if name == "ANALYSIS_PLUGIN_SPECS":
        from src.analysis.plugins import ANALYSIS_PLUGIN_SPECS

        return ANALYSIS_PLUGIN_SPECS
    if name == "ANALYSIS_PLUGIN_SPECS_BY_KEY":
        from src.analysis.plugins import ANALYSIS_PLUGIN_SPECS_BY_KEY

        return ANALYSIS_PLUGIN_SPECS_BY_KEY
    if name == "analysis_check_options":
        from src.analysis.plugins import analysis_check_options

        return analysis_check_options
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["ANALYSIS_PLUGIN_SPECS", "ANALYSIS_PLUGIN_SPECS_BY_KEY", "analysis_check_options"]
