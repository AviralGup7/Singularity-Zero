"""Reconnection support for WebSocket clients.

Provides reconnection token generation, missed message replay on reconnect,
last-sequence tracking, and a configurable reconnection window.

Tokens are now per-connection (keyed by ``user_id:fingerprint``) so a user
that has two devices open does not invalidate the other device's buffer.
Replay honours ``SubscribeMessage.resume_from`` by draining only messages
with a sequence number strictly greater than the last acknowledged
sequence, rather than returning the entire buffer.
"""

import hashlib
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

# Fix #303: use project-wide structured logger
logger = get_pipeline_logger(__name__)


@dataclass
class BufferedMessage:
    """A message held in the replay buffer.

    Attributes:
        sequence: Sequence number assigned to the original message.
        message_json: The serialized JSON representation.
    """

    sequence: int
    message_json: str

    @classmethod
    def from_envelope(cls, message_json: str) -> "BufferedMessage":
        """Extract the sequence number from a serialized message.

        Tries to parse the JSON payload to recover the original sequence
        number. Falls back to ``0`` for malformed payloads (the message
        will still be buffered and replayed if a client connects with
        ``resume_from <= 0``).
        """
        try:
            import json

            raw = json.loads(message_json)
            seq = int(raw.get("sequence", 0) or 0)
        except Exception:  # noqa: BLE001
            seq = 0
        return cls(sequence=seq, message_json=message_json)


@dataclass
class ReconnectionState:
    """State tracked for a reconnecting client.

    Attributes:
        user_id: User identifier for the client.
        fingerprint: Connection fingerprint (e.g. tab/session ID) so a
            single user can hold multiple independent replay buffers.
        last_sequence: Last sequence number the client acknowledged.
        token: Reconnection token for resuming the session.
        created_at: Unix timestamp when the token was issued.
        expires_at: Unix timestamp when the token expires.
        missed_messages: Buffered messages the client missed while disconnected.
        subscriptions: Set of channels the client was subscribed to.
    """

    user_id: str
    fingerprint: str = ""
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

        The original sequence number is captured so the replay layer can
        honour ``SubscribeMessage.resume_from``.

        Args:
            message_json: JSON string of the message to buffer.

        Returns:
            True if the message was buffered, False if dropped.
        """
        envelope = BufferedMessage.from_envelope(message_json)
        if len(self.missed_messages) >= self.max_missed_messages:
            # Fix #305: deque.popleft() is O(1) unlike list.pop(0) which is O(n)
            self.missed_messages.popleft()
            self.missed_messages.append(envelope)
            return False

        self.missed_messages.append(envelope)
        return True

    def get_replay_messages(
        self,
        resume_from: int | None = None,
    ) -> list[str]:
        """Get buffered messages for replay on reconnection.

        Implements the ``SubscribeMessage.resume_from`` contract: when a
        caller supplies ``resume_from`` (the last sequence the client
        successfully acknowledged), only messages with a strictly greater
        sequence are returned. This is the gap that previously existed
        between the protocol contract and actual replay behaviour.

        Args:
            resume_from: Optional last-acknowledged sequence number.

        Returns:
            List of JSON message strings to replay.
        """
        if resume_from is None:
            return [item.message_json for item in self.missed_messages]

        return [item.message_json for item in self.missed_messages if item.sequence > resume_from]

    def record_acknowledged_sequence(self, sequence: int) -> None:
        """Update the highest sequence number acked by the client.

        The replay filter uses this as a fallback when a reconnect
        happens without an explicit ``resume_from``.

        Args:
            sequence: The highest sequence the client has acknowledged.
        """
        if sequence > self.last_sequence:
            self.last_sequence = sequence

    def clear_buffer(self) -> None:
        """Clear the missed message buffer after successful replay."""
        self.missed_messages.clear()


class ReconnectionManager:
    """Manages WebSocket reconnection tokens and message replay.

    When a client disconnects, a reconnection token is generated that
    allows the client to resume its session within a configurable time
    window. Missed messages are buffered for replay on reconnection.

    Each token is scoped to a ``(user_id, fingerprint)`` pair so that a
    user with multiple devices or tabs receives an independent replay
    buffer per device. ``fingerprint`` defaults to a derived value when
    the caller does not supply one.

    SECURITY NOTE: Reconnection tokens should only be used to reconnect
    to the same host/origin. The validate_token method should be used
    to verify that the reconnection target matches the original connection
    to prevent connection hijacking.

    Attributes:
        reconnect_window_seconds: Seconds a reconnection token remains valid.
        max_missed_messages: Maximum messages to buffer per client.
        _tokens: Dict mapping token to ReconnectionState.
        _user_fingerprint_tokens: Dict mapping ``user_id:fingerprint`` to
            the latest reconnection token.
    """

    def __init__(
        self,
        reconnect_window_seconds: float = 120.0,
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
        # Mapping of (user_id, fingerprint) -> token. Replaces the previous
        # per-user singleton map so two devices do not share a replay
        # buffer or invalidate each other.
        self._user_fingerprint_tokens: dict[str, str] = {}

    @staticmethod
    def _fingerprint_key(user_id: str, fingerprint: str) -> str:
        return f"{user_id}:{fingerprint}"

    @staticmethod
    def derive_fingerprint(*parts: Any) -> str:
        """Derive a stable per-connection fingerprint from arbitrary parts.

        Falls back to a random 16-byte value if no parts are supplied.
        """
        if not parts:
            return secrets.token_hex(8)
        joined = "|".join(str(p) for p in parts if p is not None)
        digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
        return digest[:16]

    def generate_token(
        self,
        user_id: str,
        fingerprint: str | None = None,
    ) -> tuple[str, str]:
        """Generate a reconnection token for a user/connection pair.

        Creates a new token and invalidates any previous token for the
        *same* ``(user_id, fingerprint)`` pair. Tokens for other
        fingerprints are unaffected.

        Args:
            user_id: User identifier.
            fingerprint: Optional per-connection fingerprint. When
                ``None`` a fresh random value is generated so each
                connection that calls this method gets an independent
                replay buffer.

        Returns:
            Tuple of ``(token, fingerprint)`` so the caller can persist
            the fingerprint alongside the token.
        """
        # Fix #304: Use secrets.token_hex for cryptographically secure tokens.
        # Previous implementation used SHA-256 of predictable inputs (time, id),
        # which can be guessed if an attacker knows the approximate timestamp.
        token = secrets.token_hex(32)  # 256-bit random token
        effective_fingerprint = fingerprint or self.derive_fingerprint()
        key = self._fingerprint_key(user_id, effective_fingerprint)

        existing_token = self._user_fingerprint_tokens.get(key)
        if existing_token:
            self._tokens.pop(existing_token, None)

        # Fix #307: Enforce max_tokens limit
        if len(self._tokens) >= self.max_tokens:
            oldest_token = next(iter(self._tokens))
            oldest_state = self._tokens.pop(oldest_token)
            if oldest_state is not None:
                self._user_fingerprint_tokens.pop(
                    self._fingerprint_key(oldest_state.user_id, oldest_state.fingerprint),
                    None,
                )

        state = ReconnectionState(
            user_id=user_id,
            fingerprint=effective_fingerprint,
            token=token,
            expires_at=time.time() + self.reconnect_window_seconds,
            max_missed_messages=self.max_missed_messages,
        )

        self._tokens[token] = state
        self._user_fingerprint_tokens[key] = token

        logger.info(
            "Reconnection token generated for user %s fingerprint %s (expires in %.0fs)",
            user_id,
            effective_fingerprint,
            self.reconnect_window_seconds,
        )
        return token, effective_fingerprint

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
            self._user_fingerprint_tokens.pop(
                self._fingerprint_key(state.user_id, state.fingerprint), None
            )
            logger.info("Reconnection token expired for user %s", state.user_id)
            return None

        return state

    def buffer_message_for_user(
        self,
        user_id: str,
        message_json: str,
        fingerprint: str | None = None,
    ) -> None:
        """Buffer a missed message for a disconnected user.

        If ``fingerprint`` is provided, only that connection's buffer is
        updated. Otherwise the message is fanned out to every active
        fingerprint for the user so multiple devices each receive a
        copy.

        Args:
            user_id: User who missed the message.
            message_json: JSON string of the message.
            fingerprint: Optional connection fingerprint to target.
        """
        if fingerprint is not None:
            self._buffer_for_fingerprint(user_id, fingerprint, message_json)
            return

        prefix = f"{user_id}:"
        for key, token in list(self._user_fingerprint_tokens.items()):
            if not key.startswith(prefix):
                continue
            state = self._tokens.get(token)
            if state is None or state.is_expired():
                continue
            state.buffer_message(message_json)

    def _buffer_for_fingerprint(
        self,
        user_id: str,
        fingerprint: str,
        message_json: str,
    ) -> None:
        key = self._fingerprint_key(user_id, fingerprint)
        token = self._user_fingerprint_tokens.get(key)
        if token is None:
            return

        state = self._tokens.get(token)
        if state is None or state.is_expired():
            return

        state.buffer_message(message_json)

    def get_replay_messages(
        self,
        token: str,
        resume_from: int | None = None,
    ) -> list[str]:
        """Get buffered messages for replay after reconnection.

        Implements ``SubscribeMessage.resume_from``: when ``resume_from``
        is supplied only messages with a sequence strictly greater than
        that value are returned. When omitted, every buffered message is
        returned (preserving backward-compatible behaviour).

        Args:
            token: Valid reconnection token.
            resume_from: Optional last-acknowledged sequence number.

        Returns:
            List of JSON message strings to replay.
        """
        # Bug #40 fix: the previous implementation looked up the token
        # directly in ``self._tokens`` and replayed whatever the entry
        # contained without ever checking that the reconnection token
        # was still valid (non-expired). An attacker who obtained an old
        # (expired) token could still drain the buffered message queue
        # associated with that session. We now route the lookup through
        # ``validate_token`` so expired entries are removed and refused
        # before any replay happens.
        state = self.validate_token(token)
        if state is None:
            return []

        # Sequence-aware replay: if the client told us their last acked
        # sequence, filter the buffer so we do not replay already-seen
        # messages.
        if resume_from is None and state.last_sequence > 0:
            resume_from = state.last_sequence

        messages = state.get_replay_messages(resume_from=resume_from)
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

    def get_token_for_user(
        self,
        user_id: str,
        fingerprint: str | None = None,
    ) -> str:
        """Get the latest reconnection token for a user/connection.

        Args:
            user_id: User identifier.
            fingerprint: Optional connection fingerprint. When ``None``,
                a random fingerprint is generated, which is almost
                certainly not what callers want — prefer passing the
                real fingerprint.

        Returns:
            Latest token for the requested scope, or an empty string if
            none exists.
        """
        effective = fingerprint or self.derive_fingerprint()
        return self._user_fingerprint_tokens.get(self._fingerprint_key(user_id, effective), "")

    def record_acknowledged_sequence(self, token: str, sequence: int) -> None:
        """Persist the highest sequence acked by the client.

        Used by the message loop to remember what a client has already
        seen so a future reconnect can filter the replay buffer even
        when ``resume_from`` is not supplied.

        Args:
            token: Active reconnection token.
            sequence: Highest sequence the client has acknowledged.
        """
        state = self._tokens.get(token)
        if state is not None:
            state.record_acknowledged_sequence(sequence)

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
                self._user_fingerprint_tokens.pop(
                    self._fingerprint_key(state.user_id, state.fingerprint), None
                )

        if expired:
            logger.debug("Cleaned up %d expired reconnection tokens", len(expired))

        return len(expired)

    def invalidate_user_token(
        self,
        user_id: str,
        fingerprint: str | None = None,
    ) -> None:
        """Invalidate reconnection token(s) for a user.

        Args:
            user_id: User whose token to invalidate.
            fingerprint: Optional fingerprint. When ``None``, *all*
                tokens for the user are invalidated.
        """
        if fingerprint is None:
            prefix = f"{user_id}:"
            for key in [k for k in list(self._user_fingerprint_tokens) if k.startswith(prefix)]:
                token = self._user_fingerprint_tokens.pop(key, None)
                if token:
                    self._tokens.pop(token, None)
            return

        key = self._fingerprint_key(user_id, fingerprint)
        token = self._user_fingerprint_tokens.pop(key, None)
        if token:
            self._tokens.pop(token, None)
