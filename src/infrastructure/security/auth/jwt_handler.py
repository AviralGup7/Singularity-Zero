"""JWT token creation and validation using PyJWT."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt

from src.infrastructure.security.config import SecurityConfig

from .models import Role, TokenPayload


def encode_jwt(payload: TokenPayload, config: SecurityConfig) -> str:
    """Encode a TokenPayload into a JWT token string using PyJWT with HS256.

    SECURITY: Always uses HS256 algorithm. Never allows 'none', 'HS384',
    'HS512', or any asymmetric algorithm to prevent algorithm confusion attacks.

    Args:
        payload: Token payload to encode.
        config: Security configuration containing the signing secret.

    Returns:
        JWT token string in header.payload.signature format.
    """
    payload_dict = payload.model_dump()

    # Add standard claims if configured
    if config.jwt.issuer:
        payload_dict["iss"] = config.jwt.issuer
    if config.jwt.audience:
        payload_dict["aud"] = config.jwt.audience

    token = jwt.encode(
        payload_dict,
        config.jwt.secret,
        algorithm="HS256",
    )
    return token


def decode_jwt(token: str, config: SecurityConfig) -> TokenPayload | None:
    """Decode and validate a JWT token string using PyJWT.

    SECURITY: Enforces HS256 algorithm only - rejects 'none' and all other
    algorithms to prevent algorithm confusion attacks. Validates standard
    claims (exp, iat) and optional claims (iss, aud) if configured.

    Args:
        token: JWT token string.
        config: Security configuration for signature verification.

    Returns:
        TokenPayload if valid, None otherwise.
    """
    try:
        # Build decode options - always require exp
        options = {"require": ["exp"], "verify_exp": True}

        # Build kwargs for validation
        decode_kwargs = {
            "algorithms": ["HS256"],
            "options": options,
        }

        # Add issuer validation if configured
        if config.jwt.issuer:
            decode_kwargs["issuer"] = config.jwt.issuer

        # Add audience validation if configured
        if config.jwt.audience:
            decode_kwargs["audience"] = config.jwt.audience

        payload_data = jwt.decode(token, config.jwt.secret, **cast(Any, decode_kwargs))
        return TokenPayload(**payload_data)
    except jwt.InvalidTokenError:
        return None


def create_access_token(
    subject: str,
    role: Role,
    config: SecurityConfig,
    expires_delta: timedelta | None = None,
) -> str:
    """Create an access token with the given subject and role.

    Args:
        subject: Token subject (typically user ID or username).
        role: User role for authorization.
        config: Security configuration.
        expires_delta: Custom expiration time.

    Returns:
        Encoded JWT token string.
    """
    now = datetime.now(UTC)
    expires = now + (expires_delta or timedelta(minutes=config.jwt.access_token_expiry_minutes))

    payload = TokenPayload(
        sub=subject,
        role=role.value if isinstance(role, Role) else role,
        exp=int(expires.timestamp()),
        iat=int(now.timestamp()),
        jti=uuid.uuid4().hex,
        type="access",
    )
    return encode_jwt(payload, config)


def create_refresh_token(
    subject: str,
    config: SecurityConfig,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a refresh token for the given subject.

    Args:
        subject: Token subject (typically user ID or username).
        config: Security configuration.
        expires_delta: Custom expiration time.

    Returns:
        Encoded JWT token string.
    """
    now = datetime.now(UTC)
    expires = now + (expires_delta or timedelta(days=config.jwt.refresh_token_expiry_days))

    payload = TokenPayload(
        sub=subject,
        role="refresh",
        exp=int(expires.timestamp()),
        iat=int(now.timestamp()),
        jti=uuid.uuid4().hex,
        type="refresh",
    )
    return encode_jwt(payload, config)


def validate_token(token: str, config: SecurityConfig) -> TokenPayload | None:
    """Validate a token and return the payload if valid.

    Checks:
    1. Signature validity (HMAC-SHA256)
    2. Expiration (exp claim)
    3. Issuer (iss claim) if configured
    4. Audience (aud claim) if configured
    5. Token type ('access' or 'refresh')

    Args:
        token: JWT token string.
        config: Security configuration for validation.

    Returns:
        TokenPayload if valid and not expired, None otherwise.
    """
    payload = decode_jwt(token, config)
    if payload is None:
        return None

    return payload
