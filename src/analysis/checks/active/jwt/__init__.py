"""JWT Security Check - active JWT attack suite.

Auto-detects JWT tokens in requests/responses and runs the full
JWT attack suite against discovered tokens.

Modules:
    attacks: NoneAlgorithmAttack, AlgorithmConfusionAttack, KidPathTraversalAttack
    token_manipulation: WeakSecretAttack, JkuInjectionAttack
    expiry: LifetimeManipulationAttack
    validator: finding collectors and severity determiners
    jwt_check: Main jwt_security_analyzer() function
"""

from .attacks import (
    AlgorithmConfusionAttack,
    KidPathTraversalAttack,
    NoneAlgorithmAttack,
    b64url_decode,
    b64url_encode,
    create_jwt,
    decode_jwt_part,
)
from .expiry import LifetimeManipulationAttack
from .jwt_check import (
    CHECK_SPEC,
    JWT_AUTH_HEADERS,
    JWT_PARAM_NAMES,
    JWT_RE,
    jwt_security_analyzer,
    run_jwt_attack_suite,
)
from .token_manipulation import (
    WEAK_SECRETS,
    JkuInjectionAttack,
    WeakSecretAttack,
)
from .validator import (
    ATTACK_SEVERITY_MAP,
    SEVERITY_ORDER,
    collect_findings,
    determine_severity,
    validate_attack_result,
)

__all__ = [
    "jwt_security_analyzer",
    "run_jwt_attack_suite",
    "CHECK_SPEC",
    "JWT_RE",
    "JWT_AUTH_HEADERS",
    "JWT_PARAM_NAMES",
    "NoneAlgorithmAttack",
    "AlgorithmConfusionAttack",
    "KidPathTraversalAttack",
    "WeakSecretAttack",
    "JkuInjectionAttack",
    "LifetimeManipulationAttack",
    "collect_findings",
    "determine_severity",
    "validate_attack_result",
    "SEVERITY_ORDER",
    "ATTACK_SEVERITY_MAP",
    "decode_jwt_part",
    "create_jwt",
    "WEAK_SECRETS",
]
