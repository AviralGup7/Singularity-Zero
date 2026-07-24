"""Shared pytest fixtures and utilities for cross-module independence.

Provides fixtures that every test module can use without having to know
the internal structure of the module under test.  Import this file
indirectly by placing ``pytest_plugins = ["conftest_shared"]`` in any
test module's conftest.py, or simply rely on pytest's auto-discovery
since this file lives in the tests/ directory.

Fixtures exported:
- ``module_registry``: access to the global ``ModuleRegistry``.
- ``registered_modules``: snapshot list of all registered ``ModuleMeta``.
- ``module_health``: call ``health_check()`` on a specific module.
- ``plugin_registry``: the global ``PluginRegistry`` (auto-cleanup).
- ``clean_plugin_registry``: context manager / fixture that clears all
  registered plugins after the test.
- ``detection_plugin_registry``: the ``DETECTION_PLUGIN_SPECS`` registry.
- ``analysis_plugin_specs``: the ``ANALYSIS_PLUGIN_SPECS`` mapping.
- ``stage_registry``: the global ``StageRegistry`` (auto-cleanup).
- ``isolated_plugin_kinds``: set of all plugin kinds currently registered.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Module registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def module_registry() -> Any:
    """Return the global ``ModuleRegistry`` instance.

    The registry is populated at import time by every ``src/*/__init__.py``
    that calls ``register_module_meta``.  Tests can use this fixture to
    inspect the module graph without importing every sub-package.
    """
    from src.core.utils.shared import GLOBAL_MODULE_REGISTRY

    return GLOBAL_MODULE_REGISTRY


@pytest.fixture
def registered_modules(module_registry: Any) -> list[Any]:
    """Return a snapshot of all currently registered ``ModuleMeta`` objects."""
    return module_registry.all().values()


@pytest.fixture
def module_health(module_registry: Any) -> Any:
    """Return a callable that runs ``health_check()`` on a named module.

    Usage::

        def test_core_health(module_health):
            result = module_health("core")
            assert result["status"] == "ok"
    """

    def _check(name: str) -> dict[str, Any]:
        meta = module_registry.get(name)
        if meta is None:
            return {
                "status": "error",
                "module": name,
                "version": "unknown",
                "errors": [f"Module '{name}' is not registered"],
            }
        if not meta.health_check:
            return {
                "status": "ok",
                "module": name,
                "version": meta.version,
                "details": {"note": "module does not expose a health check"},
            }
        # Import the module's __init__ and call health_check
        import importlib

        mod = importlib.import_module(f"src.{name}")
        checker = getattr(mod, "health_check", None)
        if checker is None:
            return {
                "status": "error",
                "module": name,
                "version": meta.version,
                "errors": [f"health_check function not found in src.{name}"],
            }
        try:
            return checker()
        except Exception as exc:
            return {
                "status": "error",
                "module": name,
                "version": meta.version,
                "errors": [str(exc)],
            }

    return _check


# ---------------------------------------------------------------------------
# Plugin registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def plugin_registry() -> Any:
    """Return the global ``PluginRegistry`` instance.

    The fixture is read-only; use ``clean_plugin_registry`` for tests
    that need to register and then unregister plugins.
    """
    from src.core.plugins.registry import GLOBAL_PLUGIN_REGISTRY

    return GLOBAL_PLUGIN_REGISTRY


@pytest.fixture
def clean_plugin_registry(plugin_registry: Any) -> Generator[None]:
    """Context manager / fixture that clears all registered plugins after the test.

    Usage as a fixture::

        def test_something(clean_plugin_registry):
            # all plugins are registered during the test
            # they are automatically unregistered afterwards
            ...

    Or as a context manager::

        with clean_plugin_registry(plugin_registry):
            ...
    """
    registered: dict[str, dict[str, str]] = {}
    for kind in list(plugin_registry._providers.keys()):
        registered[kind] = dict(plugin_registry._providers[kind])
    try:
        yield
    finally:
        for kind, plugins in registered.items():
            for key in list(plugins.keys()):
                plugin_registry.unregister(kind, key)


@pytest.fixture
def isolated_plugin_kinds(plugin_registry: Any) -> set[str]:
    """Return the set of all plugin kinds currently registered."""
    return set(plugin_registry._providers.keys())


# ---------------------------------------------------------------------------
# Analysis plugin fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def analysis_plugin_specs() -> dict[str, Any]:
    """Return ``ANALYSIS_PLUGIN_SPECS_BY_KEY`` without triggering full import."""
    try:
        from src.analysis.plugins import ANALYSIS_PLUGIN_SPECS_BY_KEY

        return ANALYSIS_PLUGIN_SPECS_BY_KEY
    except ImportError:
        return {}


@pytest.fixture
def analysis_plugin_keys(analysis_plugin_specs: dict[str, Any]) -> list[str]:
    """Return the list of registered analysis plugin keys."""
    return list(analysis_plugin_specs.keys())


# ---------------------------------------------------------------------------
# Detection plugin fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def detection_plugin_registry() -> Any:
    """Return the detection plugin registry module."""
    from src.detection import registry as detection_registry

    return detection_registry


@pytest.fixture
def detection_plugin_keys(detection_plugin_registry: Any) -> list[str]:
    """Return the list of registered detection plugin keys."""
    try:
        plugins = detection_plugin_registry.list_detection_plugins()
        return [p.key for p in plugins]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Stage registry fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stage_registry() -> Any:
    """Return the global ``StageRegistry`` instance."""
    from src.pipeline.stage_registry import _global_stage_registry

    return _global_stage_registry


@pytest.fixture
def registered_stage_names(stage_registry: Any) -> list[str]:
    """Return the names of all currently registered stages."""
    return [d.name for d in stage_registry.get_all()]


# ---------------------------------------------------------------------------
# Scope / config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_scope() -> str:
    """Return a minimal scope definition string."""
    return "example.com\napi.example.com"


@pytest.fixture
def minimal_config_dict() -> dict[str, Any]:
    """Return a minimal valid Config dict."""
    return {
        "target_name": "example.com",
        "output_dir": "output",
        "concurrency": {"nuclei_workers": 2},
        "output": {"dedupe_aliases": True},
    }


# ---------------------------------------------------------------------------
# Module independence helpers
# ---------------------------------------------------------------------------


def assert_module_meta_registered(name: str, module_registry: Any) -> Any:
    """Assert that a module with *name* is registered in the module registry.

    Returns the ``ModuleMeta`` for the module so the test can make
    further assertions about version, layer, or dependencies.
    """
    meta = module_registry.get(name)
    assert meta is not None, f"Module '{name}' is not registered in the module registry"
    return meta


def assert_no_circular_lazy_imports(module_name: str) -> None:
    """Assert that importing *module_name* does not raise ImportError.

    This is a lightweight smoke test that catches broken lazy-import
    facades without exercising the full module graph.
    """
    import importlib

    mod = importlib.import_module(f"src.{module_name}")
    assert mod is not None


# ---------------------------------------------------------------------------
# Pytest plugin marker (auto-discovered by pytest when this file is in tests/)
# ---------------------------------------------------------------------------

pytest_plugins = ["tests.conftest"]
