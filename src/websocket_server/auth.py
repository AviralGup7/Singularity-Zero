"""WebSocket authentication middleware.

Provides token-based authentication for WebSocket connections supporting
JWT tokens via query parameter or subprotocol, API key fallback, and
structured auth error responses.
"""

import json
from dataclasses import dataclass
from typing import Any

from starlette.websockets import WebSocket

from src.core.logging.trace_logging import get_pipeline_logger

# Fix #270: use project-wide structured logger
logger = get_pipeline_logger(__name__)


@dataclass
class AuthCredentials:
    """Authenticated principal extracted from a WebSocket connection request.

    Attributes:
        user_id: Unique user identifier.
        roles: Set of role strings assigned to the user.
        api_key_id: API key identifier if authenticated via API key.
        token_payload: Raw JWT payload claims if authenticated via JWT.
        auth_method: Method used for authentication ('jwt', 'api_key', 'subprotocol').
    """

    user_id: str
    roles: set[str]
    api_key_id: str | None = None
    token_payload: dict[str, Any] | None = None
    auth_method: str = "unknown"


class AuthenticationError(Exception):
    """Raised when WebSocket authentication fails.

    Attributes:
        code: Machine-readable error code.
        detail: Human-readable error description.
        status_code: WebSocket close code to send (defaults to 4001).
    """

    def __init__(
        self,
        code: str,
        detail: str,
        status_code: int = 4001,
    ) -> None:
        self.code = code
        self.detail = detail
        self.status_code = status_code
        super().__init__(detail)


async def authenticate_websocket(
    websocket: WebSocket,
    jwt_secret: str | None = None,
    jwt_algorithms: list[str] | None = None,
    api_keys: dict[str, str] | None = None,
    required_roles: set[str] | None = None,
) -> AuthCredentials:
    """Authenticate a WebSocket connection.

    Attempts authentication in the following order:
    1. JWT token from query parameter ``?token=<jwt>``
    2. JWT token from subprotocol header ``Sec-WebSocket-Protocol: bearer.<jwt>``
    3. API key from query parameter ``?api_key=<key>``

    Args:
        websocket: The incoming WebSocket connection.
        jwt_secret: Secret key for JWT validation. If None, JWT auth is skipped.
        jwt_algorithms: Allowed JWT algorithms (default: ``["HS256"]``).
        api_keys: Dict mapping API key strings to user IDs. If None, API key auth is skipped.
        required_roles: If set, the authenticated user must have at least one of these roles.

    Returns:
        AuthCredentials if authentication succeeds.

    Raises:
        AuthenticationError: If authentication fails.
    """
    algorithms = jwt_algorithms or ["HS256"]

    subprotocols = websocket.headers.get("sec-websocket-protocol", "")
    for protocol in subprotocols.split(","):
        protocol = protocol.strip()
        if protocol.startswith("bearer.") and jwt_secret:
            jwt_token = protocol[len("bearer.") :]
            return _authenticate_jwt(jwt_token, jwt_secret, algorithms, required_roles)

    api_key_header = websocket.headers.get("x-api-key")
    if api_key_header and api_keys:
        return _authenticate_api_key(api_key_header, api_keys, required_roles)

    # Keep WebSocket behavior consistent with HTTP endpoints in development:
    # when no auth backend is configured, allow anonymous access.
    if jwt_secret is None and not api_keys:
        anonymous_roles = {"anonymous"}
        if required_roles and not anonymous_roles.intersection(required_roles):
            raise AuthenticationError(
                code="auth_insufficient_roles",
                detail=f"Required roles: {required_roles}, got: {anonymous_roles}",
                status_code=4003,
            )
        # Fix #274: Guard against websocket.client being None (e.g. during tests).
        client_ip = websocket.client.host if websocket.client else "unknown"
        return AuthCredentials(
            user_id=f"anonymous:{client_ip}",
            roles=anonymous_roles,
            auth_method="none",
        )

    raise AuthenticationError(
        code="auth_missing_credentials",
        detail="No valid authentication credentials provided. Use Sec-WebSocket-Protocol: bearer.<jwt> or x-api-key.",
        status_code=4001,
    )


def _authenticate_jwt(
    token: str,
    secret: str,
    algorithms: list[str],
    required_roles: set[str] | None,
) -> AuthCredentials:
    """Validate a JWT token and extract user credentials.

    Args:
        token: JWT token string.
        secret: Secret key for signature verification.
        algorithms: Allowed algorithms.
        required_roles: Required role set for access.

    Returns:
        AuthCredentials extracted from the JWT claims.

    Raises:
        AuthenticationError: If the token is invalid or expired.
    """
    try:
        import jwt as pyjwt
    except ImportError:
        raise AuthenticationError(
            code="auth_internal_error",
            detail="JWT library not available",
            status_code=4001,
        )

    try:
        # Fix #273: Hardcode HS256 — ignore caller-supplied algorithms to prevent
        # algorithm confusion attacks (e.g. passing ["none"] or ["RS256"]).
        payload = pyjwt.decode(token, secret, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise AuthenticationError(
            code="auth_token_expired",
            detail="Authentication token has expired",
            status_code=4001,
        )
    except pyjwt.InvalidTokenError as exc:
        raise AuthenticationError(
            code="auth_token_invalid",
            detail=f"Invalid authentication token: {exc}",
            status_code=4001,
        )

    user_id = payload.get("sub") or payload.get("user_id")
    if not user_id:
        raise AuthenticationError(
            code="auth_token_missing_subject",
            detail="Token missing 'sub' or 'user_id' claim",
            status_code=4001,
        )

    roles = set(payload.get("roles", []))
    if isinstance(payload.get("roles"), str):
        roles = {payload["roles"]}

    if required_roles and not roles.intersection(required_roles):
        raise AuthenticationError(
            code="auth_insufficient_roles",
            detail=f"Required roles: {required_roles}, got: {roles}",
            status_code=4003,
        )

    return AuthCredentials(
        user_id=str(user_id),
        roles=roles,
        token_payload=payload,
        auth_method="jwt",
    )


def _authenticate_api_key(
    api_key: str,
    api_keys: dict[str, str],
    required_roles: set[str] | None,
) -> AuthCredentials:
    """Validate an API key and return user credentials.

    Args:
        api_key: API key string to validate.
        api_keys: Dict mapping valid API keys to user IDs.
        required_roles: Required role set for access.

    Returns:
        AuthCredentials for the API key owner.

    Raises:
        AuthenticationError: If the API key is invalid.
    """
    user_id = api_keys.get(api_key)
    if user_id is None:
        raise AuthenticationError(
            code="auth_api_key_invalid",
            detail="Invalid API key",
            status_code=4001,
        )

    roles = {"api_key_user"}
    if ":" in user_id:
        maybe_role, _identifier = user_id.split(":", 1)
        if maybe_role:
            roles = {maybe_role}

    if required_roles and not roles.intersection(required_roles):
        raise AuthenticationError(
            code="auth_insufficient_roles",
            detail=f"Required roles: {required_roles}, got: {roles}",
            status_code=4003,
        )

    return AuthCredentials(
        user_id=user_id,
        roles=roles,
        api_key_id=api_key[:8] + "...",
        auth_method="api_key",
    )


async def send_auth_error(websocket: WebSocket, error: AuthenticationError) -> None:
    """Send an authentication error response and close the WebSocket.

    Sends a JSON error message before closing the connection with the
    appropriate close code.

    Args:
        websocket: The WebSocket connection to close.
        error: The authentication error to report.
    """
    try:
        await websocket.accept()
        error_payload = json.dumps(
            {
                "type": "error",
                "code": error.code,
                "message": error.detail,
                "recoverable": False,
            }
        )
        await websocket.send_text(error_payload)
        await websocket.close(code=error.status_code, reason=error.detail)
    except Exception:
        try:
            await websocket.close(code=error.status_code)
        except Exception as e:
            logger.debug("Failed to close websocket during auth error: %s", e)
