"""Environment variable and cache-based secret management."""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.infrastructure.security.config import SecurityConfig
    from src.infrastructure.security.encryption import DataEncryptor

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class SecretManager:
    """Environment variable and vault-based secret management.

    Provides secure access to secrets with support for:
    - Environment variables
    - Encrypted environment variables
    - File-based secrets
    - In-memory secret caching
    """

    def __init__(
        self,
        config: SecurityConfig,
        cache_max_size: int = 100,
        cache_ttl_seconds: float = 3600,
    ) -> None:
        """Initialize the secret manager.

        Args:
            config: Security configuration.
            cache_max_size: Maximum number of secrets to cache (LRU eviction).
            cache_ttl_seconds: Seconds before cached secrets expire.
        """
        import collections
        from src.infrastructure.security.encryption import DataEncryptor  # Avoid circular imports

        self.config = config
        self._encryptor: DataEncryptor | None = None
        self._cache: dict[str, tuple[str, float]] = {}  # {name: (value, expires_at)}
        self._cache_max_size = cache_max_size
        self._cache_ttl = cache_ttl_seconds
        self._cache_order: collections.OrderedDict[str, None] = (
            collections.OrderedDict()
        )  # LRU tracking

        if config.encryption.fernet_key:
            try:
                self._encryptor = DataEncryptor(config.encryption.fernet_key)
            except ValueError:
                logger.warning("Invalid encryption key, secret encryption disabled")

    def _cache_get(self, name: str) -> str | None:
        """Get a cached secret if it hasn't expired. Implements LRU eviction."""
        if name in self._cache:
            value, expires_at = self._cache[name]
            if time.time() < expires_at:
                self._cache_order.move_to_end(name)
                return value
            else:
                self._cache_del(name)
        return None

    def _cache_set(self, name: str, value: str) -> None:
        """Store a secret in the cache with TTL. Evicts oldest if full."""
        expires_at = time.time() + self._cache_ttl

        if name in self._cache:
            self._cache[name] = (value, expires_at)
            self._cache_order.move_to_end(name)
            return

        while len(self._cache) >= self._cache_max_size:
            oldest_name, _ = self._cache_order.popitem(last=False)
            self._cache.pop(oldest_name, None)

        self._cache[name] = (value, expires_at)
        self._cache_order[name] = None

    def _cache_del(self, name: str) -> None:
        """Remove a secret from the cache."""
        self._cache.pop(name, None)
        self._cache_order.pop(name, None)

    def get_secret(self, name: str, default: str | None = None) -> str | None:
        """Get a secret from cache (with TTL) or environment.

        Args:
            name: Secret name (environment variable name).
            default: Default value if not found.

        Returns:
            Secret value or default.
        """
        cached = self._cache_get(name)
        if cached is not None:
            return cached

        value = os.environ.get(name)
        if value is not None:
            self._cache_set(name, value)
            return value

        return default

    def get_secret_required(self, name: str) -> str:
        """Get a required secret, raising an error if not found.

        Args:
            name: Secret name.

        Returns:
            Secret value.

        Raises:
            ValueError: If the secret is not set.
        """
        value = self.get_secret(name)
        if value is None:
            raise ValueError(f"Required secret {name} is not set")
        return value

    def get_encrypted_secret(self, name: str, default: str | None = None) -> str | None:
        """Get and decrypt an encrypted secret.

        Args:
            name: Secret name.
            default: Default value if not found.

        Returns:
            Decrypted secret value or default.
        """
        encrypted = self.get_secret(name)
        if encrypted is None:
            return default

        if self._encryptor is None:
            logger.warning("Encryption not available, returning raw secret")
            return encrypted

        try:
            return self._encryptor.decrypt(encrypted)
        except Exception as exc:
            logger.error("Failed to decrypt secret %s: %s", name, exc)
            return default

    def set_secret(self, name: str, value: str) -> None:
        """Set a secret in the cache (not in environment).

        Args:
            name: Secret name.
            value: Secret value.
        """
        self._cache_set(name, value)

    def set_encrypted_secret(self, name: str, value: str) -> str | None:
        """Encrypt and store a secret.

        Args:
            name: Secret name.
            value: Secret value to encrypt.

        Returns:
            Encrypted value string, or None if encryption unavailable.
        """
        if self._encryptor is None:
            return None

        encrypted = self._encryptor.encrypt(value)
        self._cache_set(name, encrypted)
        return encrypted

    def clear_cache(self) -> None:
        """Clear the in-memory secret cache."""
        self._cache.clear()
        self._cache_order.clear()

    def hash_secret(self, value: str, salt: str | None = None) -> str:
        """Hash a secret value for storage.

        Args:
            value: Secret value to hash.
            salt: Optional salt (generated if not provided).

        Returns:
            Hex-encoded hash string with salt prefix.
        """
        if salt is None:
            salt = os.urandom(16).hex()

        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            value.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        )
        return f"{salt}:{hashed.hex()}"

    def verify_hashed_secret(self, value: str, stored: str) -> bool:
        """Verify a secret against a stored hash.

        Args:
            value: Secret value to verify.
            stored: Stored hash string (salt:hash format).

        Returns:
            True if the secret matches.
        """
        parts = stored.split(":")
        if len(parts) != 2:
            return False

        salt, expected_hash = parts
        computed = hashlib.pbkdf2_hmac(
            "sha256",
            value.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        ).hex()

        return hmac_module.compare_digest(computed, expected_hash)
