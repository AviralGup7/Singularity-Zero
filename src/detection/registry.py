"""Detection plugin registry providing metadata about available analyzers.

Defines DetectionPlugin dataclass and builds the DETECTION_PLUGINS tuple
from analysis plugin specifications, adding phase, input kind, and
consumes/produces metadata from analyzer bindings.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from src.analysis.plugin_runtime import (
    ANALYZER_BINDING,
    ANALYZER_BINDINGS,
    AnalysisExecutionContext,
    run_registered_analyzer,
)
from src.analysis.plugins import DETECTOR_SPEC
from src.core.plugins import list_plugins

logger = logging.getLogger(__name__)


# Default confidence assigned to a plugin when the binding does not declare
# a specific baseline. Active probes that produce direct evidence (sqli_safe,
# ssrf_active, etc.) override this through the analyzer binding.
_DEFAULT_PLUGIN_CONFIDENCE = 0.50
_ACTIVE_PROBE_CONFIDENCE = 0.65
_RUNTIME_CONFIDENCE = 0.70

_ACTIVE_PROBE_KEYS = frozenset(
    {
        "sqli_safe_probe",
        "ssrf_active_probe",
        "path_traversal_active_probe",
        "command_injection_active_probe",
        "xxe_active_probe",
        "crlf_injection_probe",
        "host_header_injection_probe",
        "ssti_active_probe",
        "nosql_injection_probe",
        "deserialization_probe",
        "open_redirect_active_probe",
        "xpath_injection_probe",
        "hpp_active_probe",
        "jwt_manipulation_probe",
        "websocket_hijacking_probe",
        "idor_active_probe",
        "file_upload_active_probe",
        "cookie_manipulation_probe",
        "csrf_active_probe",
        "reflected_xss_probe",
        "http_smuggling_probe",
        "http2_probe",
        "ssrf_oob_validator",
        "auth_bypass_check",
        "access_control_analyzer",
    }
)

_RUNTIME_DETECTION_KEYS = frozenset(
    {
        "cognitive_flow_analysis",
        "behavior_analysis_layer",
        "race_condition_signal_analyzer",
        "flow_detector",
        "multi_step_flow_breaking_probe",
        "state_transition_analyzer",
        "csrf_active_probe",
    }
)


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
    baseline_confidence: float = _DEFAULT_PLUGIN_CONFIDENCE
    detection_tier: str = "passive"
    recommended_engines: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)


def _classify_plugin(key: str) -> tuple[float, str, tuple[str, ...], tuple[str, ...]]:
    """Return (baseline_confidence, detection_tier, recommended_engines, tags).

    `detection_tier` is one of: passive, active, runtime, browser, ast, stateful.
    """

    if key in _ACTIVE_PROBE_KEYS:
        return (
            _ACTIVE_PROBE_CONFIDENCE,
            "active",
            ("httpexploitengine",),
            ("active", "probe"),
        )
    if key in _RUNTIME_DETECTION_KEYS:
        return (
            _RUNTIME_CONFIDENCE,
            "runtime",
            ("httpexploitengine",),
            ("runtime", "stateful"),
        )
    if key in {"dom_xss_signal_detector", "stored_xss_signal_detector"}:
        return (
            0.55,
            "browser",
            ("injectionengine",),
            ("dom", "browser"),
        )
    if key in {
        "js_sink_source_analyzer",
        "wasm_module_introspector",
        "prototype_pollution_walker",
    }:
        return (
            0.60,
            "ast",
            ("httpexploitengine",),
            ("ast", "static"),
        )
    if key in {
        "csrf_entropy_analyzer",
        "session_fixation_detector",
        "rate_limit_adaptive_prober",
        "race_concurrent_mutator",
    }:
        return (
            0.60,
            "stateful",
            ("httpexploitengine",),
            ("stateful", "session"),
        )
    if key in {"waf_fingerprint_analyzer", "waf_challenge_detector"}:
        return (
            0.70,
            "active",
            ("headerinjectionengine",),
            ("waf", "fingerprint"),
        )
    if "smuggling" in key or "h2" in key or "double_encoding" in key:
        return (
            0.70,
            "active",
            ("headerinjectionengine",),
            ("smuggling", "protocol"),
        )
    if "header_injection" in key or "host_header" in key:
        return (
            0.55,
            "active",
            ("headerinjectionengine", "authbypassengine"),
            ("header", "injection"),
        )
    if "ssrf" in key or "proxy_ssrf" in key:
        return (
            0.55,
            "active",
            ("ssrfexploitationengine",),
            ("ssrf",),
        )
    if "ssti" in key:
        return (
            0.55,
            "active",
            ("sstiexploitationengine",),
            ("ssti",),
        )
    if "deserial" in key:
        return (
            0.55,
            "active",
            ("deserializationexploitationengine",),
            ("deserialization",),
        )
    if "sqli" in key:
        return (
            0.55,
            "active",
            ("injectionengine",),
            ("sqli",),
        )
    if "path_traversal" in key or "lfi" in key:
        return (
            0.55,
            "active",
            ("pathtraversalexploitationengine",),
            ("path_traversal",),
        )
    if "file_upload" in key or "upload" in key:
        return (
            0.50,
            "active",
            ("fileuploadexploitationengine",),
            ("upload",),
        )
    if "race" in key:
        return (
            0.55,
            "runtime",
            ("raceconditionengine",),
            ("race",),
        )
    if key in {
        "api_rest_param_pollution",
        "api_graphql_introspection",
        "api_rate_limit_differential",
        "api_jwt_claim_integrity",
        "api_websocket_message_security",
    }:
        engines_lookup: dict[str, tuple[str, ...]] = {
            "api_rest_param_pollution": ("injectionengine",),
            "api_graphql_introspection": ("injectionengine",),
            "api_rate_limit_differential": ("raceconditionengine",),
            "api_jwt_claim_integrity": ("authbypassengine", "headerinjectionengine"),
            "api_websocket_message_security": ("injectionengine", "headerinjectionengine"),
        }
        return (
            0.55,
            "passive",
            engines_lookup.get(key, ()),
            ("api",),
        )
    return (_DEFAULT_PLUGIN_CONFIDENCE, "passive", (), ())


def _build_detection_plugins() -> tuple[DetectionPlugin, ...]:
    specs = {reg.key: reg.provider for reg in list_plugins(DETECTOR_SPEC)}
    bindings = {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}

    plugins: list[DetectionPlugin] = []
    for key, binding in bindings.items():
        spec = specs.get(key)
        label = spec.label if spec else key.replace("_", " ").title()
        group = spec.group if spec else "custom"
        enabled_by_default = spec.enabled_by_default if spec else True
        baseline, tier, engines, tags = _classify_plugin(key)
        plugins.append(
            DetectionPlugin(
                key=key,
                label=label,
                group=group,
                input_kind=binding.input_kind,
                enabled_by_default=enabled_by_default,
                phase=binding.phase,
                consumes=binding.consumes,
                produces=binding.produces,
                baseline_confidence=baseline,
                detection_tier=tier,
                recommended_engines=engines,
                tags=tags,
            )
        )
    return tuple(plugins)


def list_detection_plugins() -> tuple[DetectionPlugin, ...]:
    return _build_detection_plugins()


DETECTION_PLUGINS: tuple[DetectionPlugin, ...]
DETECTION_PLUGINS_BY_KEY: dict[str, DetectionPlugin]


def __getattr__(name: str) -> Any:
    if name == "DETECTION_PLUGINS":
        return list_detection_plugins()
    if name == "DETECTION_PLUGINS_BY_KEY":
        return {p.key: p for p in list_detection_plugins()}
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


_DETECTION_PLUGIN_OPTIONS: list[dict[str, Any]] | None = None


def get_detection_plugin(plugin_key: str) -> DetectionPlugin:
    normalized = plugin_key.strip()
    plugins = {p.key: p for p in list_detection_plugins()}
    plugin = plugins.get(normalized)
    if plugin is None:
        available = ", ".join(sorted(plugins.keys()))
        logger.warning(
            "Failed to resolve detection plugin key: '%s' (normalized: '%s'). Available keys: %s",
            plugin_key,
            normalized,
            available,
        )
        raise KeyError(
            f"Unknown detection plugin '{plugin_key}' (normalized: '{normalized}'). "
            f"Available plugins: {available}"
        )
    logger.debug("Successfully resolved detection plugin: %s", normalized)
    return plugin


def run_detection_plugin(
    plugin_key: str, context: AnalysisExecutionContext
) -> list[dict[str, Any]]:
    plugin = get_detection_plugin(plugin_key)
    binding = ANALYZER_BINDINGS.get(plugin.key)
    if binding is None:
        # Fallback to dynamic lookup in list_plugins
        bindings = {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}
        binding = bindings.get(plugin.key)
    if binding is None:
        raise KeyError(f"No analyzer binding found for plugin key '{plugin.key}'")
    logger.info("Running detection plugin: %s", plugin.key)
    results = run_registered_analyzer(binding, context)
    logger.info("Detection plugin %s returned %d results", plugin.key, len(results))
    return results


def detection_plugin_options() -> list[dict[str, object]]:
    global _DETECTION_PLUGIN_OPTIONS
    if _DETECTION_PLUGIN_OPTIONS is None:
        logger.info("Initializing detection plugin options cache")
        specs = {reg.key: reg.provider for reg in list_plugins(DETECTOR_SPEC)}
        _DETECTION_PLUGIN_OPTIONS = [
            {
                "name": plugin.key,
                "label": plugin.label,
                "description": specs[plugin.key].description if plugin.key in specs else "",
                "group": plugin.group,
                "input_kind": plugin.input_kind,
                "enabled_by_default": plugin.enabled_by_default,
                "phase": plugin.phase,
                "consumes": list(plugin.consumes),
                "produces": list(plugin.produces),
                "baseline_confidence": plugin.baseline_confidence,
                "detection_tier": plugin.detection_tier,
                "recommended_engines": list(plugin.recommended_engines),
                "tags": list(plugin.tags),
            }
            for plugin in list_detection_plugins()
        ]
    return [opt.copy() for opt in _DETECTION_PLUGIN_OPTIONS]
