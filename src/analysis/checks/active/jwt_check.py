"""JWT Security Check - active JWT attack suite.

This module re-exports the main jwt_security_analyzer function
from the jwt/ package for backward compatibility with existing imports.

See jwt/ package for the modular implementation:
    jwt/attacks.py            - NoneAlgorithmAttack, AlgorithmConfusionAttack, KidPathTraversalAttack
    jwt/token_manipulation.py  - WeakSecretAttack, JkuInjectionAttack
    jwt/expiry.py              - LifetimeManipulationAttack
    jwt/validator.py           - finding collectors and severity determiners
    jwt/jwt_check.py           - Main jwt_security_analyzer() coordinator
"""

from src.analysis.checks.active.jwt import jwt_security_analyzer

__all__ = ["jwt_security_analyzer"]
