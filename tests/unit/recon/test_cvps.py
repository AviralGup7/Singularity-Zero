"""Unit tests for the Contextual Vulnerability Priority Scoring (CVPS) Engine."""

from __future__ import annotations

from src.recon.cvps import compute_cvps_score


def test_compute_cvps_score_sensitive_parameters():
    """Verify that sensitive parameter keywords correctly trigger a major boost."""
    url1 = "https://example.com/api/v1/users?ssn_id=123"
    url2 = "https://example.com/api/v1/users?card_number=456"
    url3 = "https://example.com/api/v1/health"

    score1 = compute_cvps_score(url1)
    score2 = compute_cvps_score(url2)
    score3 = compute_cvps_score(url3)

    assert score1 >= 8.5
    assert score2 >= 8.5
    assert score3 == 0.0  # Safe/healthy path


def test_compute_cvps_score_non_standard_ports():
    """Verify that non-standard ports (like 8080/8443) trigger risk boosts."""
    url = "https://example.com/api/v1/admin"

    # Base port 443
    score_standard = compute_cvps_score(url, port=443)
    # Exposed microservice port 8080
    score_exposed = compute_cvps_score(url, port=8080)

    assert score_exposed > score_standard
    assert score_exposed >= 6.5  # Port risk + base


def test_compute_cvps_score_profile_alignment():
    """Verify that context heavy profile ratios align and trigger boosts."""
    url_api = "https://example.com/api/v1/endpoints"
    url_auth = "https://example.com/login"

    profile = {
        "api_heavy": True,
        "auth_heavy": True,
    }

    score_api = compute_cvps_score(url_api, context_profile=profile)
    score_auth = compute_cvps_score(url_auth, context_profile=profile)

    assert score_api >= 3.5
    assert score_auth >= 4.5
