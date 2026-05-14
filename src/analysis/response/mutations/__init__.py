"""Mutation-based attack probes for response analysis.

Re-exports all public functions from sub-modules for backward compatibility.
"""

from src.analysis.response.mutations.auth_tampering import (
    auth_header_tampering_variations,
)
from src.analysis.response.mutations.diff import (
    _flatten_json,
    _variant_diff_summary,
)
from src.analysis.response.mutations.http_methods import (
    _http_method_probe,
    _redirect_target,
    http_method_override_probe,
    multi_step_flow_breaking_probe,
)
from src.analysis.response.mutations.json_mutation import (
    json_mutation_attacks,
)
from src.analysis.response.mutations.parameter_pollution import (
    parameter_pollution_exploitation,
)
from src.analysis.response.mutations.post_body import (
    post_body_mutation_attacks,
)

__all__ = [
    "_variant_diff_summary",
    "_flatten_json",
    "parameter_pollution_exploitation",
    "auth_header_tampering_variations",
    "json_mutation_attacks",
    "post_body_mutation_attacks",
    "http_method_override_probe",
    "_http_method_probe",
    "multi_step_flow_breaking_probe",
    "_redirect_target",
]
