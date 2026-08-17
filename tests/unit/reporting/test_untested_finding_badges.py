"""Coverage for MITRE / CVSS / correlation badge renderers."""

from __future__ import annotations

import pytest

from src.reporting.finding_badges import (
    MITRE_TECHNIQUE_NAMES,
    render_attack_chain_badge,
    render_correlation_badge,
    render_cvss_badge,
    render_mitre_badge_for_access_control,
    render_mitre_badge_for_auth_bypass,
    render_mitre_badges,
    render_model_badge,
)


@pytest.mark.unit
def test_render_mitre_badges_empty() -> None:
    assert render_mitre_badges([]) == ""


@pytest.mark.unit
def test_render_mitre_badges_uses_catalog_and_escapes() -> None:
    html = render_mitre_badges(
        [
            {"technique_id": "T1190", "tactic": "Initial Access"},
            {"technique_id": "T9999", "technique_name": "Custom <script>", "tactic": "x"},
            {"technique_id": "T1078", "tactic": "Persistence"},
            {"technique_id": "T1110", "tactic": "Credential Access"},
        ]
    )
    assert "T1190: Exploit Public-Facing Application" in html
    assert "T1078: Valid Accounts" in html
    assert "T1110" not in html  # limited to 3
    assert "<script>" not in html
    assert "mitre-badge" in html


@pytest.mark.unit
def test_auth_bypass_and_access_control_defaults() -> None:
    auth = render_mitre_badge_for_auth_bypass({})
    access = render_mitre_badge_for_access_control({})
    assert "T1078" in auth and "T1134" in auth
    assert "T1190" in access and "T1078" in access
    custom = render_mitre_badge_for_auth_bypass(
        {"mitre_attack": [{"technique_id": "T1110", "tactic": "Credential Access"}]}
    )
    assert "T1110" in custom


@pytest.mark.unit
def test_correlation_and_attack_chain_badges() -> None:
    assert render_correlation_badge({}) == ""
    html = render_correlation_badge(
        {"attack_chains": ["ssrf_to_rce", "token_replay", "ignored_third"]}
    )
    assert "Ssrf To Rce" in html
    assert "Token Replay" in html
    assert "ignored_third" not in html
    assert render_attack_chain_badge({}) == ""
    chained = render_attack_chain_badge({"evidence": {"attack_chain": "ssrf->imds"}})
    assert "ssrf-&gt;imds" in chained or "ssrf->imds" in chained


@pytest.mark.unit
@pytest.mark.parametrize(
    ("severity", "color"),
    [
        ("critical", "#cc0000"),
        ("high", "#ff6600"),
        ("medium", "#ffcc00"),
        ("low", "#33cc33"),
        ("none", "#959595"),
        ("weird", "#959595"),
    ],
)
def test_cvss_badge_colors(severity: str, color: str) -> None:
    assert render_cvss_badge({}) == ""
    html = render_cvss_badge(
        {"cvss": {"base_score": 9.1, "vector_string": "CVSS:3.1/AV:N", "severity": severity}}
    )
    assert "CVSS 9.1" in html
    assert color in html
    assert severity.upper() in html


@pytest.mark.unit
def test_model_badge_includes_signal_quality() -> None:
    assert render_model_badge({}) == ""
    html = render_model_badge(
        {
            "severity_score": 0.81,
            "severity_model": {"true_positive_probability": 0.9, "training_samples": 12},
            "signal_quality": {"quality_score": 77, "action": "keep"},
            "false_positive_probability": 0.1,
        }
    )
    assert "ML 0.81" in html
    assert "Signal 77" in html


@pytest.mark.unit
def test_mitre_catalog_has_core_techniques() -> None:
    for key in ("T1190", "T1059", "T1078", "T1110", "T1552"):
        assert key in MITRE_TECHNIQUE_NAMES
        assert MITRE_TECHNIQUE_NAMES[key]
