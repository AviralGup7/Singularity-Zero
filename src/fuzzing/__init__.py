"""Fuzzing orchestration, generators, mutators, and strategies."""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "fuzzing",
    "version": "3.1.0",
    "description": (
        "Fuzzing orchestration, generators, mutators, and strategies "
        "for AST, coverage-guided, differential, stateful, and workflow fuzzing."
    ),
    "layer": "fuzzing",
    "submodules": ("generators", "mutators", "strategies"),
    "public_api": (
        "CorpusManager",
        "CoverageTracker",
        "ForkServer",
        "WorkflowFuzzer",
        "EndpointNode",
        "StopCondition",
        "run_coverage_guided_campaign",
        "run_differential_fuzzing_campaign",
        "run_framing_fuzzing_campaign",
        "run_h2_fuzzing_campaign",
        "run_stateful_fuzzing_campaign",
    ),
    "depends_on": ("core",),
    "entry_points": (),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify fuzzing subsystem health.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``errors``.
    """
    try:
        from src.fuzzing.coverage_guided import CorpusManager  # noqa: F401
        from src.fuzzing.orchestrator import FuzzingOrchestrator  # noqa: F401

        return {
            "status": "ok",
            "module": "fuzzing",
            "version": "3.1.0",
            "details": {
                "coverage_guided": "available",
                "orchestrator": "available",
            },
        }
    except ImportError as exc:
        return {
            "status": "degraded",
            "module": "fuzzing",
            "version": "3.1.0",
            "errors": [str(exc)],
        }


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

# ---------------------------------------------------------------------------
# Public API re-exports (unchanged)
# ---------------------------------------------------------------------------

from .coverage_guided import CorpusManager, CoverageTracker, run_coverage_guided_campaign
from .diff_utils import compute_diff_ratio, find_byte_level_diffs, normalize_response
from .differential_fuzzer import GoldenResponseStore, run_differential_fuzzing_campaign
from .fork_server import ForkServer
from .framing_fuzzer import run_framing_fuzzing_campaign
from .generators.dockerfile_fuzzer import scan_for_secrets
from .generators.graphql_payloads import generate_graphql_introspection_payloads
from .generators.jwt_payloads import (
    fuzz_jwt_claims,
    fuzz_jwt_header,
    generate_malformed_jwt,
)
from .generators.protobuf_payloads import (
    invalid_varint,
    missing_required_field,
    recursive_depth_bomb,
    wrong_wire_type,
)
from .generators.xml_payloads import (
    generate_billion_laughs,
    generate_external_dtd,
    generate_malformed_xml,
    generate_xxe_payload,
)
from .h2_fuzzer import run_h2_fuzzing_campaign
from .payload_generator import generate_parameter_payloads, generate_payload_suggestions
from .payload_generator_http import (
    HEADER_PAYLOADS,
    INJECTABLE_HEADERS,
    generate_body_payloads,
    generate_header_payloads,
)
from .stateful_fuzzer import run_stateful_fuzzing_campaign
from .stop_conditions import (
    StopCondition,
    StopOnFirstFinding,
    StopOnN,
    StopOnPattern,
    StopOnSeverity,
)
from .workflow_fuzzer import (
    EndpointNode,
    WorkflowFuzzer,
)

__all__ = [
    "generate_parameter_payloads",
    "generate_payload_suggestions",
    "generate_header_payloads",
    "generate_body_payloads",
    "generate_graphql_introspection_payloads",
    "generate_malformed_jwt",
    "fuzz_jwt_header",
    "fuzz_jwt_claims",
    "generate_xxe_payload",
    "generate_billion_laughs",
    "generate_external_dtd",
    "generate_malformed_xml",
    "invalid_varint",
    "wrong_wire_type",
    "recursive_depth_bomb",
    "missing_required_field",
    "scan_for_secrets",
    "INJECTABLE_HEADERS",
    "HEADER_PAYLOADS",
    "run_framing_fuzzing_campaign",
    "run_graphql_fuzzing_campaign",
    "run_h2_fuzzing_campaign",
    "run_quic_fuzzing_campaign",
    "CorpusManager",
    "CoverageTracker",
    "run_coverage_guided_campaign",
    "ForkServer",
    "StopCondition",
    "StopOnFirstFinding",
    "StopOnN",
    "StopOnPattern",
    "StopOnSeverity",
    "EndpointNode",
    "WorkflowFuzzer",
]
