from typing import Any


# Lazy imports to avoid circular dependency
def __getattr__(name: str) -> Any:
    if name == "generate_run_report":
        from src.reporting.pages import generate_run_report as _gen

        return _gen
    import src.reporting.pipeline as _mod

    if hasattr(_mod, name):
        return getattr(_mod, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
