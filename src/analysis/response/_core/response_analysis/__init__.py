"""Response analysis module for behavioral testing and mutation-based detection.

Provides functions for response snapshotting, diff analysis, flow detection,
redirect chain analysis, parameter pollution exploitation, auth header
tampering, and JSON mutation attacks.

This package modularizes the response analysis into separate files
for better maintainability and AI-agent editability.
"""

from src.analysis.helpers import JSON_CONTENT_TOKENS

from ._auth_tampering import auth_header_tampering_variations
from ._classification import build_mutation_strategy_coverage, build_response_classification_summary
from ._diff_engine import response_diff_engine
from ._diff_utils import variant_diff_summary as _variant_diff_summary
from ._flow_detection import flow_detector, multi_step_flow_breaking_probe
from ._http_method_override import http_method_override_probe
from ._json_mutations import json_mutation_attacks, post_body_mutation_attacks
from ._parameter_pollution import parameter_pollution_exploitation
from ._redirect_analysis import auth_boundary_redirect_detection, redirect_chain_analyzer
from ._snapshot import response_snapshot_system

# Backwards-compatible alias for code using the old name

JSON_CONTENT_HINTS = JSON_CONTENT_TOKENS


__all__ = [
    "JSON_CONTENT_HINTS",
    "response_snapshot_system",
    "response_diff_engine",
    "flow_detector",
    "parameter_pollution_exploitation",
    "auth_header_tampering_variations",
    "json_mutation_attacks",
    "post_body_mutation_attacks",
    "multi_step_flow_breaking_probe",
    "http_method_override_probe",
    "redirect_chain_analyzer",
    "auth_boundary_redirect_detection",
    "build_response_classification_summary",
    "build_mutation_strategy_coverage",
    "_variant_diff_summary",
]
