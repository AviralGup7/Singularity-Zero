"""VRT (Vulnerability Rating Taxonomy) coverage mapping for pipeline findings.

Maps pipeline detection signals to Bugcrowd VRT categories and severity levels,
enabling coverage reporting against industry-standard vulnerability classifications.
"""

from typing import Any

from src.core.models import Config

P1_VRT_CATALOG = [
    {
        "technical_severity": "P1",
        "vrt_category": "AI Application Security",
        "vulnerability_name": "Model Extraction",
        "variant": "API Query-Based Model Reconstruction",
        "direct_checks": [],
        "signal_checks": [
            "ai_endpoint_exposure_analyzer",
            "rate_limit_header_analyzer",
            "rate_limit_signal_analyzer",
        ],
        "notes": "The pipeline can identify exposed AI inference surfaces and weak throttling signals, but it does not perform direct model reconstruction testing.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "AI Application Security",
        "vulnerability_name": "Remote Code Execution",
        "variant": "Full System Compromise",
        "direct_checks": [],
        "signal_checks": ["server_side_injection_surface_analyzer"],
        "notes": "Only suspicious execution and command-style sinks are surfaced. No exploit validation is attempted.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "AI Application Security",
        "vulnerability_name": "Sensitive Information Disclosure",
        "variant": "Cross-Tenant PII Leakage/Exposure",
        "direct_checks": [
            "cross_tenant_pii_risk_analyzer",
            "cross_user_access_simulation",
            "sensitive_field_detector",
        ],
        "signal_checks": ["role_based_endpoint_comparison", "access_boundary_tracker"],
        "notes": "Passive cross-tenant and identity-boundary indicators are implemented, but analyst verification is still required.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "AI Application Security",
        "vulnerability_name": "Sensitive Information Disclosure",
        "variant": "Key Leak",
        "direct_checks": [
            "sensitive_data_scanner",
            "token_leak_detector",
            "third_party_key_exposure_checker",
        ],
        "signal_checks": ["ai_endpoint_exposure_analyzer"],
        "notes": "Secret, token, and provider-key exposure is directly scanned in responses and URLs.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "AI Application Security",
        "vulnerability_name": "Training Data Poisoning",
        "variant": "Backdoor Injection / Bias Manipulation",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "Training pipeline integrity and poisoning scenarios are not modeled in the current codebase.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Automotive Security Misconfiguration",
        "vulnerability_name": "Infotainment, Radio Head Unit",
        "variant": "Sensitive data Leakage/Exposure",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "Automotive-specific protocols, firmware, and telemetry flows are unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Automotive Security Misconfiguration",
        "vulnerability_name": "RF Hub",
        "variant": "Key Fob Cloning",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "RF, CAN, and key-fob attack paths are outside this HTTP-focused pipeline.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Broken Access Control (BAC)",
        "vulnerability_name": "Insecure Direct Object References (IDOR)",
        "variant": "Modify/View Sensitive Information(Iterable Object Identifiers)",
        "direct_checks": [
            "idor_candidate_finder",
            "cross_user_access_simulation",
            "role_based_endpoint_comparison",
            "validate_idor_candidates",
        ],
        "signal_checks": ["response_diff_engine", "bulk_endpoint_detector"],
        "notes": "Dedicated IDOR discovery, comparison, and evidence promotion are implemented.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Broken Authentication and Session Management",
        "vulnerability_name": "Authentication Bypass",
        "variant": "",
        "direct_checks": ["unauth_access_check", "multi_endpoint_auth_consistency_check"],
        "signal_checks": ["access_boundary_tracker", "auth_boundary_redirect_detection"],
        "notes": "Unauthenticated replay and inconsistent auth enforcement checks are implemented.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Cloud Security",
        "vulnerability_name": "Identity and Access Management (IAM) Misconfigurations",
        "variant": "Publicly Accessible IAM Credentials",
        "direct_checks": [
            "sensitive_data_scanner",
            "environment_file_exposure_checker",
            "public_repo_exposure_checker",
        ],
        "signal_checks": ["third_party_key_exposure_checker"],
        "notes": "Exposed credentials and secrets in public assets are directly scanned.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Decentralized Application Misconfiguration",
        "vulnerability_name": "Insecure Data Storage",
        "variant": "Plaintext Private Key",
        "direct_checks": ["sensitive_data_scanner"],
        "signal_checks": [],
        "notes": "Private key block and secret exposure patterns are directly scanned.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Decentralized Application Misconfiguration",
        "vulnerability_name": "Marketplace Security",
        "variant": "Orderbook Manipulation",
        "direct_checks": [],
        "signal_checks": [
            "parameter_dependency_tracker",
            "state_transition_analyzer",
            "race_condition_signal_analyzer",
        ],
        "notes": "Business-logic and race-condition signals exist, but DEX/orderbook-specific testing is not implemented.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Decentralized Application Misconfiguration",
        "vulnerability_name": "Marketplace Security",
        "variant": "Signer Account Takeover",
        "direct_checks": [],
        "signal_checks": ["token_leak_detector", "sensitive_data_scanner"],
        "notes": "Key and token exposure is covered, but signer-wallet takeover workflows are not modeled.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Decentralized Application Misconfiguration",
        "vulnerability_name": "Marketplace Security",
        "variant": "Unauthorized Asset Transfer",
        "direct_checks": [],
        "signal_checks": ["state_transition_analyzer", "parameter_dependency_tracker"],
        "notes": "Generic business-logic coverage exists, but chain-aware asset-transfer validation is unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Decentralized Application Misconfiguration",
        "vulnerability_name": "Protocol Security Misconfiguration",
        "variant": "Node-level Denial of Service",
        "direct_checks": [],
        "signal_checks": ["rate_limit_signal_analyzer"],
        "notes": "Only weak throttling signals are surfaced. Node-layer DoS testing is unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Insecure OS/Firmware",
        "vulnerability_name": "Command Injection",
        "variant": "",
        "direct_checks": [],
        "signal_checks": ["server_side_injection_surface_analyzer"],
        "notes": "The pipeline can identify suspicious command-execution surfaces, but not safely validate firmware-level compromise.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Insecure OS/Firmware",
        "vulnerability_name": "Hardcoded Password",
        "variant": "Privileged User",
        "direct_checks": ["sensitive_data_scanner", "default_credential_hints"],
        "signal_checks": ["environment_file_exposure_checker"],
        "notes": "Hardcoded secrets and bootstrap/default credential surfaces are scanned passively.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Sensitive Data Exposure",
        "vulnerability_name": "Disclosure of Secrets",
        "variant": "For Publicly Accessible Asset",
        "direct_checks": [
            "sensitive_data_scanner",
            "environment_file_exposure_checker",
            "log_file_exposure_checker",
            "public_repo_exposure_checker",
            "backup_file_exposure_checker",
        ],
        "signal_checks": ["frontend_config_exposure_checker", "third_party_key_exposure_checker"],
        "notes": "Publicly accessible secrets, backups, logs, repo metadata, and config leaks are directly scanned.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Server Security Misconfiguration",
        "vulnerability_name": "Exposed Portal",
        "variant": "Admin Portal",
        "direct_checks": ["admin_panel_path_detection", "exposed_service_detection"],
        "signal_checks": ["default_credential_hints"],
        "notes": "Admin portals and exposed management surfaces are directly enumerated.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Server Security Misconfiguration",
        "vulnerability_name": "Using Default Credentials",
        "variant": "",
        "direct_checks": ["default_credential_hints"],
        "signal_checks": ["admin_panel_path_detection"],
        "notes": "Default-credential hints are based on exposed services and login surfaces.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Server-Side Injection",
        "vulnerability_name": "File Inclusion",
        "variant": "Local",
        "direct_checks": [],
        "signal_checks": ["server_side_injection_surface_analyzer"],
        "notes": "Local file inclusion is surfaced through file/path/include indicators only.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Server-Side Injection",
        "vulnerability_name": "Remote Code Execution (RCE)",
        "variant": "",
        "direct_checks": [],
        "signal_checks": ["server_side_injection_surface_analyzer"],
        "notes": "The pipeline surfaces suspicious execution sinks, but does not run exploit code.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Server-Side Injection",
        "vulnerability_name": "SQL Injection",
        "variant": "",
        "direct_checks": [],
        "signal_checks": ["server_side_injection_surface_analyzer", "error_based_inference"],
        "notes": "SQLi-oriented parameters and backend SQL error signals are surfaced, but not directly exploited.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Server-Side Injection",
        "vulnerability_name": "XML External Entity Injection (XXE)",
        "variant": "",
        "direct_checks": [],
        "signal_checks": ["server_side_injection_surface_analyzer"],
        "notes": "Only XML/DTD/XXE-oriented request surfaces are identified.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Smart Contract Misconfiguration",
        "vulnerability_name": "Reentrancy Attack",
        "variant": "",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "Smart-contract bytecode and transaction-sequencing analysis are unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Smart Contract Misconfiguration",
        "vulnerability_name": "Smart Contract Owner Takeover",
        "variant": "",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "On-chain ownership and admin-control logic are unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Smart Contract Misconfiguration",
        "vulnerability_name": "Unauthorized Transfer of Funds",
        "variant": "",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "Transfer-function and state-machine analysis for contracts is unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Smart Contract Misconfiguration",
        "vulnerability_name": "Uninitialized Variables",
        "variant": "",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "Compiler and deployment-state contract analysis are unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Zero Knowledge Security Misconfiguration",
        "vulnerability_name": "Deanonymization of Data",
        "variant": "",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "Zero-knowledge and privacy-preserving circuit analysis are unsupported.",
    },
    {
        "technical_severity": "P1",
        "vrt_category": "Zero Knowledge Security Misconfiguration",
        "vulnerability_name": "Improper Proof Validation and Finalization Logic",
        "variant": "",
        "direct_checks": [],
        "signal_checks": [],
        "notes": "Proof verification, settlement, and finalization logic are unsupported.",
    },
]


from src.core.plugins import register_plugin

ENRICHMENT_PROVIDER = "enrichment_provider"


@register_plugin(ENRICHMENT_PROVIDER, "p1_vrt_coverage")
def build_p1_vrt_coverage(config: Config) -> dict[str, Any]:
    entries = []
    counts = {
        "requested_total": len(P1_VRT_CATALOG),
        "direct": 0,
        "signal_only": 0,
        "disabled": 0,
        "unsupported": 0,
    }
    for spec in P1_VRT_CATALOG:
        direct_active = sorted(
            check for check in spec["direct_checks"] if _check_enabled(config, check)
        )
        signal_active = sorted(
            check for check in spec["signal_checks"] if _check_enabled(config, check)
        )
        known_checks = [*spec["direct_checks"], *spec["signal_checks"]]
        if direct_active:
            status = "direct"
        elif signal_active:
            status = "signal_only"
        elif known_checks:
            status = "disabled"
        else:
            status = "unsupported"
        counts[status] += 1
        entries.append(
            {
                "technical_severity": spec["technical_severity"],
                "vrt_category": spec["vrt_category"],
                "vulnerability_name": spec["vulnerability_name"],
                "variant": spec["variant"],
                "status": status,
                "active_checks": [*direct_active, *signal_active],
                "direct_checks": list(spec["direct_checks"]),
                "signal_checks": list(spec["signal_checks"]),
                "notes": spec["notes"],
            }
        )
    return {
        "summary": counts,
        "entries": entries,
        "unsupported_entries": [item for item in entries if item["status"] == "unsupported"],
        "disabled_entries": [item for item in entries if item["status"] == "disabled"],
    }


def _check_enabled(config: Config, check_name: str) -> bool:
    if check_name == "validate_idor_candidates":
        return bool(config.analysis.get("idor_candidate_finder", True))
    return bool(config.analysis.get(check_name, True))
