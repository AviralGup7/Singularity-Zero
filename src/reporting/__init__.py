# Lazy imports to avoid circular dependency
def __getattr__(name: str):
    if name == "generate_run_report":
        from src.reporting.pages import generate_run_report as _gen

        return _gen
    import src.reporting.pipeline as _mod

    return getattr(_mod, name, None)
