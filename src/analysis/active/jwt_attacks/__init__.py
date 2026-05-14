"""JWT Attack Suite - comprehensive JWT vulnerability testing."""

from .alg_none_attack import test_alg_none
from .claim_manipulation import test_claim_manipulation
from .expiration_bypass import test_expiration_bypass
from .jku_x5u_injection import test_jku_injection
from .key_confusion import test_algorithm_confusion
from .kid_injection import test_kid_traversal
from .token_replay import test_token_replay
from .weak_secret import test_weak_secret

__all__ = [
    "test_alg_none",
    "test_algorithm_confusion",
    "test_kid_traversal",
    "test_claim_manipulation",
    "test_token_replay",
    "test_expiration_bypass",
    "test_jku_injection",
    "test_weak_secret",
    "run_jwt_attack_suite",
]


def run_jwt_attack_suite(token: str, url: str, session, config=None) -> dict:
    """Run the full JWT attack suite against a target URL."""
    import logging

    logger = logging.getLogger(__name__)
    logger.info("Starting JWT attack suite on %s", url)

    attacks = {
        "alg_none": test_alg_none(token, url, session),
        "algorithm_confusion": test_algorithm_confusion(token, url, session),
        "kid_traversal": test_kid_traversal(token, url, session),
        "claim_manipulation": test_claim_manipulation(token, url, session),
        "token_replay": test_token_replay(token, url, session),
        "expiration_bypass": test_expiration_bypass(token, url, session),
        "jku_injection": test_jku_injection(token, url, session),
        "weak_secret": test_weak_secret(token, url, session),
    }

    vulnerable_attacks = [name for name, result in attacks.items() if result.get("vulnerable")]
    total_tests = len(attacks)
    vulnerable_count = len(vulnerable_attacks)

    severity = (
        "critical"
        if vulnerable_count >= 3
        else "high"
        if vulnerable_count >= 2
        else "medium"
        if vulnerable_count >= 1
        else "info"
    )

    findings = []
    for name, result in attacks.items():
        if result.get("vulnerable"):
            for detail in result.get("details", []):
                findings.append(
                    {
                        "attack": name,
                        "finding": detail.get("finding", name),
                        "status_code": detail.get("status_code"),
                        "original_status": detail.get("original_status"),
                        "auth_header": detail.get("auth_header"),
                    }
                )

    return {
        "url": url,
        "token_preview": token[:30] + "..." if len(token) > 30 else token,
        "total_attacks": total_tests,
        "vulnerable_attacks": vulnerable_count,
        "vulnerable_list": vulnerable_attacks,
        "severity": severity,
        "attacks": attacks,
        "findings": findings,
    }
