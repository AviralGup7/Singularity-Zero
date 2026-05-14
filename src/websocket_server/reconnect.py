"""Reconnection support for WebSocket clients.

Provides reconnection token generation, missed message replay on reconnect,
last-sequence tracking, and a configurable reconnection window.
"""

import secrets
import time
from collections import deque
from dataclasses import dataclass, field

from src.core.logging.trace_logging import get_pipeline_logger

# Fix #303: use project-wide structured logger
logger = get_pipeline_logger(__name__)


@dataclass
class ReconnectionState:
    """State tracked for a reconnecting client.

    Attributes:
        user_id: User identifier for the client.
        last_sequence: Last sequence number the client acknowledged.
        token: Reconnection token for resuming the session.
        created_at: Unix timestamp when the token was issued.
        expires_at: Unix timestamp when the token expires.
        missed_messages: Buffered messages the client missed while disconnected.
        subscriptions: Set of channels the client was subscribed to.
    """

    user_id: str
    last_sequence: int = 0
    token: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    missed_messages: deque = field(  # Fix #305: deque for O(1) pop from front
        default_factory=deque
    )
    subscriptions: set[str] = field(default_factory=set)
    max_missed_messages: int = field(default=500)

    def is_expired(self) -> bool:
        """Check if the reconnection token has expired.

        Returns:
            True if the current time is past the expiration time.
        """
        return time.time() > self.expires_at

    def buffer_message(self, message_json: str) -> bool:
        """Buffer a missed message for potential replay.

        Drops the oldest message if the buffer is full to prevent
        unbounded memory growth. Uses deque for O(1) operations.

        Args:
            message_json: JSON string of the message to buffer.

        Returns:
            True if the message was buffered, False if dropped.
        """
        if len(self.missed_messages) >= self.max_missed_messages:
            # Fix #305: deque.popleft() is O(1) unlike list.pop(0) which is O(n)
            self.missed_messages.popleft()
            self.missed_messages.append(message_json)
            return False

        self.missed_messages.append(message_json)
        return True

    def get_replay_messages(self) -> list[str]:
        """Get buffered messages for replay on reconnection.

        Returns:
            List of JSON message strings to replay.
        """
        # Fix #352: Removed unused from_sequence parameter.
        return list(self.missed_messages)

    def clear_buffer(self) -> None:
        """Clear the missed message buffer after successful replay."""
        self.missed_messages.clear()


class ReconnectionManager:
    """Manages WebSocket reconnection tokens and message replay.

    When a client disconnects, a reconnection token is generated that
    allows the client to resume its session within a configurable time
    window. Missed messages are buffered for replay on reconnection.

    Attributes:
        reconnect_window_seconds: Seconds a reconnection token remains valid.
        max_missed_messages: Maximum messages to buffer per client.
        _tokens: Dict mapping token to ReconnectionState.
        _user_tokens: Dict mapping user_id to their latest reconnection token.
    """

    def __init__(
        self,
        reconnect_window_seconds: float = 300.0,
        max_missed_messages: int = 500,
        max_tokens: int = 10000,
    ) -> None:
        """Initialize the reconnection manager.

        Args:
            reconnect_window_seconds: Validity window for reconnection tokens.
            max_missed_messages: Max messages to buffer per disconnected client.
            max_tokens: Max anonymous tokens to store before evicting oldest.
        """
        self.reconnect_window_seconds = reconnect_window_seconds
        self.max_missed_messages = max_missed_messages
        self.max_tokens = max_tokens
        self._tokens: dict[str, ReconnectionState] = {}
        self._user_tokens: dict[str, str] = {}

    def generate_token(self, user_id: str) -> str:
        """Generate a reconnection token for a user.

        Creates a new token and invalidates any previous token for the
        same user.

        Args:
            user_id: User identifier.

        Returns:
            Opaque reconnection token string.
        """
        # Fix #304: Use secrets.token_hex for cryptographically secure tokens.
        # Previous implementation used SHA-256 of predictable inputs (time, id),
        # which can be guessed if an attacker knows the approximate timestamp.
        token = secrets.token_hex(32)  # 256-bit random token

        existing_token = self._user_tokens.get(user_id)
        if existing_token:
            self._tokens.pop(existing_token, None)

        # Fix #307: Enforce max_tokens limit
        if len(self._tokens) >= self.max_tokens:
            oldest_token = next(iter(self._tokens))
            oldest_state = self._tokens.pop(oldest_token)
            self._user_tokens.pop(oldest_state.user_id, None)

        state = ReconnectionState(
            user_id=user_id,
            token=token,
            expires_at=time.time() + self.reconnect_window_seconds,
            max_missed_messages=self.max_missed_messages,
        )

        self._tokens[token] = state
        self._user_tokens[user_id] = token

        logger.info(
            "Reconnection token generated for user %s (expires in %.0fs)",
            user_id,
            self.reconnect_window_seconds,
        )
        return token

    def validate_token(self, token: str) -> ReconnectionState | None:
        """Validate a reconnection token and return its state.

        Args:
            token: Reconnection token from the client.

        Returns:
            ReconnectionState if valid and not expired, None otherwise.
        """
        state = self._tokens.get(token)
        if state is None:
            return None

        if state.is_expired():
            self._tokens.pop(token, None)
            self._user_tokens.pop(state.user_id, None)
            logger.info("Reconnection token expired for user %s", state.user_id)
            return None

        return state

    def buffer_message_for_user(self, user_id: str, message_json: str) -> None:
        """Buffer a missed message for a disconnected user.

        Args:
            user_id: User who missed the message.
            message_json: JSON string of the message.
        """
        token = self._user_tokens.get(user_id)
        if token is None:
            return

        state = self._tokens.get(token)
        if state is None or state.is_expired():
            return

        state.buffer_message(message_json)

    def get_replay_messages(
        self,
        token: str,
    ) -> list[str]:
        """Get buffered messages for replay after reconnection.

        Args:
            token: Valid reconnection token.

        Returns:
            List of JSON message strings to replay.
        """
        state = self._tokens.get(token)
        if state is None:
            return []

        # Fix #352: Removed unused from_sequence parameter.
        messages = state.get_replay_messages()
        state.clear_buffer()
        return messages

    def record_subscriptions(self, token: str, channels: set[str]) -> None:
        """Record the channels a client was subscribed to.

        Args:
            token: Reconnection token.
            channels: Set of channel names.
        """
        state = self._tokens.get(token)
        if state:
            state.subscriptions.update(channels)

    def get_subscriptions(self, token: str) -> set[str]:
        """Get the channels a client was subscribed to before disconnecting.

        Args:
            token: Reconnection token.

        Returns:
            Set of channel names.
        """
        state = self._tokens.get(token)
        if state is None:
            return set()
        return set(state.subscriptions)

    def get_token_for_user(self, user_id: str) -> str:
        """Get the latest reconnection token for a user.

        Args:
            user_id: User identifier.

        Returns:
            Latest token for the user, or an empty string if none exists.
        """
        return self._user_tokens.get(user_id, "")

    def cleanup_expired(self) -> int:
        """Remove all expired reconnection tokens.

        Returns:
            Number of expired tokens removed.
        """
        # Fix #306: removed dead `time.time()` call whose return value was discarded.
        expired = [token for token, state in self._tokens.items() if state.is_expired()]

        for token in expired:
            state = self._tokens.pop(token, None)
            if state:
                self._user_tokens.pop(state.user_id, None)

        if expired:
            logger.debug("Cleaned up %d expired reconnection tokens", len(expired))

        return len(expired)

    def invalidate_user_token(self, user_id: str) -> None:
        """Invalidate the current reconnection token for a user.

        Args:
            user_id: User whose token to invalidate.
        """
        token = self._user_tokens.pop(user_id, None)
        if token:
            self._tokens.pop(token, None)
