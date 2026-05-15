"""API key generation, validation, rotation, and revocation."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from src.infrastructure.security.config import SecurityConfig

from .models import APIKey, Role


def generate_api_key(config: SecurityConfig) -> str:
    """Generate a raw API key string with the configured prefix.

    Args:
        config: Security configuration containing the key prefix.

    Returns:
        Raw API key string (prefix + random hex).
    """
    return config.api_key.key_prefix + secrets.token_hex(32)


def hash_api_key(raw_key: str) -> str:
    """Compute SHA-256 hash of an API key.

    Args:
        raw_key: Raw API key string.

    Returns:
        Hex-encoded SHA-256 hash.
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class APIKeyStore:
    """In-memory store and lifecycle manager for API keys.

    Attributes:
        config: Security configuration.
        _api_keys: Dict mapping key_hash -> APIKey.
        _user_api_keys: Dict mapping user_id -> list of key hashes.
    """

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the API key store.

        Args:
            config: Security configuration.
        """
        self.config = config
        self._api_keys: dict[str, APIKey] = {}
        self._user_api_keys: dict[str, list[str]] = {}

    def create(
        self,
        user_id: str,
        name: str,
        role: Role = Role.VIEWER,
        expires_days: int | None = None,
    ) -> tuple[str, APIKey]:
        """Create a new API key for a user.

        Args:
            user_id: Owner user ID.
            name: Human-readable key name.
            role: Role associated with this key.
            expires_days: Days until key expires (None for no expiry).

        Returns:
            Tuple of (raw_key, APIKey model). The raw key is only
            returned once and must be stored securely by the caller.

        Raises:
            ValueError: If user has reached maximum key limit.
        """
        user_keys = self._user_api_keys.get(user_id, [])
        active_keys = [
            kid for kid in user_keys if kid in self._api_keys and self._api_keys[kid].is_valid
        ]

        if len(active_keys) >= self.config.api_key.max_keys_per_user:
            raise ValueError(
                f"User {user_id} has reached the maximum of "
                f"{self.config.api_key.max_keys_per_user} API keys"
            )

        raw_key = generate_api_key(self.config)
        key_hash = hash_api_key(raw_key)
        key_prefix = raw_key[:16]

        now = datetime.now(UTC)
        expires_at: float | None = None
        if expires_days is not None:
            expires_at = (now + timedelta(days=expires_days)).timestamp()
        elif self.config.api_key.rotation_days > 0:
            expires_at = (now + timedelta(days=self.config.api_key.rotation_days)).timestamp()

        api_key = APIKey(
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            role=role,
            expires_at=expires_at,
        )

        self._api_keys[key_hash] = api_key
        if user_id not in self._user_api_keys:
            self._user_api_keys[user_id] = []
        self._user_api_keys[user_id].append(key_hash)

        return raw_key, api_key

    def validate(self, raw_key: str) -> APIKey | None:
        """Validate an API key and return its model if valid.

        Args:
            raw_key: Raw API key string.

        Returns:
            APIKey if valid, None otherwise.
        """
        key_hash = hash_api_key(raw_key)
        api_key = self._api_keys.get(key_hash)

        if api_key is None or not api_key.is_valid:
            return None

        api_key.last_used_at = datetime.now(UTC).timestamp()
        return api_key

    def rotate(self, key_id: str) -> tuple[str, APIKey] | None:
        """Rotate an API key by revoking the old one and creating a new one.

        Args:
            key_id: ID of the key to rotate.

        Returns:
            Tuple of (new_raw_key, new_APIKey) or None if key not found.
        """
        old_key = None
        for key_hash, api_key in self._api_keys.items():
            if api_key.id == key_id:
                old_key = api_key
                break

        if old_key is None:
            return None

        old_key.is_active = False

        new_raw_key, new_key = self.create(
            user_id=old_key.user_id,
            name=f"{old_key.name} (rotated)",
            role=old_key.role,
        )

        return new_raw_key, new_key

    def revoke(self, key_id: str) -> bool:
        """Revoke an API key.

        Args:
            key_id: ID of the key to revoke.

        Returns:
            True if the key was found and revoked.
        """
        for api_key in self._api_keys.values():
            if api_key.id == key_id:
                api_key.is_revoked = True
                api_key.is_active = False
                return True
        return False

    def list_keys(self, user_id: str) -> list[APIKey]:
        """List all API keys for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of APIKey models.
        """
        key_ids = self._user_api_keys.get(user_id, [])
        return [key for key_hash, key in self._api_keys.items() if key_hash in key_ids]
