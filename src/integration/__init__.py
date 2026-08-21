"""UI-backend integration protocol for the Security Console."""

from src.integration.commands import CATALOG, CommandName, get_command
from src.integration.envelope import RequestEnvelope, ResponseEnvelope
from src.integration.errors import ErrorCode, IntegrationError
from src.integration.protocol import PROTOCOL_VERSION

__all__ = [
    "CATALOG",
    "CommandName",
    "ErrorCode",
    "IntegrationError",
    "PROTOCOL_VERSION",
    "RequestEnvelope",
    "ResponseEnvelope",
    "get_command",
]
