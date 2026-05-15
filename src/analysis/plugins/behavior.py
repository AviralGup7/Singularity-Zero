from .base import AnalysisPluginSpec, spec

BEHAVIOR_PLUGIN_SPECS: tuple[AnalysisPluginSpec, ...] = (
    spec(
        "response_diff_engine",
        "Response Diff Engine",
        "Compare safe parameter mutations and highlight status, redirect, and content changes.",
        "logic",
    ),
    spec(
        "multi_step_flow_breaking_probe",
        "Multi-Step Flow Breaking",
        "Attempt direct access to later workflow steps and flag flows that appear reachable out of sequence.",
        "logic",
    ),
    spec(
        "smart_payload_suggestions",
        "Payload Suggestions",
        "Generate non-executing test variants for redirect, ID, token, and callback-style parameters.",
        "logic",
    ),
    spec(
        "filter_parameter_fuzzer",
        "Filter Parameter Fuzzer",
        "Toggle safe filter parameters and look for hidden states, roles, or global views.",
        "logic",
    ),
    spec(
        "error_based_inference",
        "Error-Based Inference",
        "Use safe invalid values to extract backend field names and hidden parameter hints.",
        "logic",
    ),
    spec(
        "state_transition_analyzer",
        "State Transition Analyzer",
        "Mutate state and step parameters to detect before/after workflow mismatches.",
        "logic",
    ),
    spec(
        "parameter_dependency_tracker",
        "Parameter Dependency Tracker",
        "Track whether price, quantity, discount, scope, and role fields react together.",
        "logic",
    ),
    spec(
        "flow_integrity_checker",
        "Flow Integrity Checker",
        "Detect repeated or out-of-order flow stages that suggest step skipping.",
        "logic",
    ),
    spec(
        "race_condition_signal_analyzer",
        "Race Condition Signals",
        "Highlight booking, checkout, claim, coupon, and other stateful endpoints that look concurrency-sensitive.",
        "logic",
    ),
    spec(
        "version_diffing",
        "Version Diffing",
        "Compare alternate API versions for auth, content, and behavior differences.",
        "logic",
    ),
    spec(
        "payment_flow_intelligence",
        "Payment Flow Intelligence",
        "Identify checkout, billing, refund, and subscription-oriented routes and parameters.",
        "logic",
    ),
    spec(
        "payment_provider_detection",
        "Payment Provider Detection",
        "Detect payment provider references that help map logic-sensitive checkout flows.",
        "logic",
    ),
    spec(
        "behavior_analysis_layer",
        "Behavior Analysis",
        "Replay controlled single-parameter variants, track flow shifts, and store reproducible evidence for review.",
        "logic",
    ),
    spec(
        "server_side_injection_surface_analyzer",
        "Server-Side Injection Surface",
        "Flag SQLi, file inclusion, XXE, command, and RCE-style parameter surfaces from passive evidence.",
        "logic",
    ),
)
