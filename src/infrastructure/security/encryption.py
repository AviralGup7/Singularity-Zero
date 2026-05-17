"""Encryption utilities for the Cyber Security Test Pipeline.

Provides data-at-rest encryption, API key encryption, TLS configuration
recommendations, and secret management utilities.

Functions:
    generate_fernet_key: Generate a new Fernet encryption key
    encrypt_data: Encrypt data using Fernet symmetric encryption
    decrypt_data: Decrypt data using Fernet symmetric encryption
    encrypt_string: Encrypt a string value
    decrypt_string: Decrypt a string value

Classes:
    DataEncryptor: Fernet-based encryptor for sensitive data
    SecretManager: Environment variable and vault-based secret management
    TLSConfig: TLS configuration recommendations

Usage:
    from src.infrastructure.security.encryption import DataEncryptor, generate_fernet_key

    key = generate_fernet_key()
    encryptor = DataEncryptor(key)

    encrypted = encryptor.encrypt("sensitive data")
    decrypted = encryptor.decrypt(encrypted)
"""

import base64
import hashlib
import hmac as hmac_module
import os
from typing import Any, cast

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.config import SecurityConfig

logger = get_pipeline_logger(__name__)


def generate_fernet_key() -> str:
    """Generate a new Fernet encryption key.

    Returns:
        URL-safe base64-encoded Fernet key string.
    """
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode("utf-8")


def encrypt_data(data: bytes, key: str) -> bytes:
    """Encrypt data using Fernet symmetric encryption.

    Args:
        data: Raw bytes to encrypt.
        key: Fernet key string.

    Returns:
        Encrypted bytes (includes IV and authentication tag).
    """
    from cryptography.fernet import Fernet

    fernet = Fernet(key.encode("utf-8"))
    return fernet.encrypt(data)


def decrypt_data(encrypted_data: bytes, key: str) -> bytes:
    """Decrypt data using Fernet symmetric encryption.

    Args:
        encrypted_data: Encrypted bytes from encrypt_data().
        key: Fernet key string.

    Returns:
        Decrypted raw bytes.

    Raises:
        cryptography.fernet.InvalidToken: If the key is wrong or data is tampered.
    """
    from cryptography.fernet import Fernet

    fernet = Fernet(key.encode("utf-8"))
    return fernet.decrypt(encrypted_data)


def encrypt_string(value: str, key: str) -> str:
    """Encrypt a string value.

    Args:
        value: String to encrypt.
        key: Fernet key string.

    Returns:
        URL-safe base64-encoded encrypted string.
    """
    encrypted = encrypt_data(value.encode("utf-8"), key)
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_string(encrypted_value: str, key: str) -> str:
    """Decrypt a string value.

    Args:
        encrypted_value: Encrypted string from encrypt_string().
        key: Fernet key string.

    Returns:
        Decrypted string.

    Raises:
        cryptography.fernet.InvalidToken: If the key is wrong or data is tampered.
    """
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_value)
    decrypted = decrypt_data(encrypted_bytes, key)
    return decrypted.decode("utf-8")


def redis_tls_kwargs_from_env() -> dict[str, Any]:
    """Build redis-py TLS kwargs from environment variables."""
    import ssl

    kwargs: dict[str, Any] = {}
    ca_certs = os.environ.get("REDIS_TLS_CA_CERTS") or os.environ.get("SEC_REDIS_TLS_CA_CERTS")
    certfile = os.environ.get("REDIS_TLS_CERTFILE") or os.environ.get("SEC_REDIS_TLS_CERTFILE")
    keyfile = os.environ.get("REDIS_TLS_KEYFILE") or os.environ.get("SEC_REDIS_TLS_KEYFILE")
    cert_reqs = (
        os.environ.get("REDIS_TLS_CERT_REQS")
        or os.environ.get("SEC_REDIS_TLS_CERT_REQS")
        or "required"
    ).lower()

    if ca_certs:
        kwargs["ssl_ca_certs"] = ca_certs
        kwargs["ssl_cert_reqs"] = {
            "none": ssl.CERT_NONE,
            "optional": ssl.CERT_OPTIONAL,
            "required": ssl.CERT_REQUIRED,
        }.get(cert_reqs, ssl.CERT_REQUIRED)
    if certfile:
        kwargs["ssl_certfile"] = certfile
    if keyfile:
        kwargs["ssl_keyfile"] = keyfile
    return kwargs


class DataEncryptor:
    """Fernet-based encryptor for sensitive data.

    Provides convenient methods for encrypting and decrypting
    various data types used in the pipeline.

    Attributes:
        key: Fernet encryption key.
        _fernet: Underlying Fernet instance.
    """

    def __init__(self, key: str) -> None:
        """Initialize the data encryptor.

        Args:
            key: Fernet encryption key.

        Raises:
            ValueError: If the key is invalid.
        """
        from cryptography.fernet import Fernet

        if not key:
            raise ValueError("Encryption key cannot be empty")

        try:
            self._fernet = Fernet(key.encode("utf-8"))
            self.key = key
        except Exception as exc:
            raise ValueError(f"Invalid Fernet key: {exc}") from exc

    def encrypt(self, data: str | bytes | dict[str, Any]) -> str:
        """Encrypt data of various types.

        Args:
            data: String, bytes, or dictionary to encrypt.

        Returns:
            Base64-encoded encrypted string.
        """
        import json

        if isinstance(data, bytes):
            raw = data
        elif isinstance(data, str):
            raw = data.encode("utf-8")
        else:
            raw = json.dumps(data, separators=(",", ":")).encode("utf-8")

        encrypted = self._fernet.encrypt(raw)
        return base64.urlsafe_b64encode(encrypted).decode("utf-8")

    def decrypt(self, encrypted: str) -> str:
        """Decrypt a string and return the plaintext.

        Args:
            encrypted: Base64-encoded encrypted string.

        Returns:
            Decrypted string.
        """
        encrypted_bytes = base64.urlsafe_b64decode(encrypted)
        decrypted = self._fernet.decrypt(encrypted_bytes)
        return decrypted.decode("utf-8")

    def decrypt_bytes(self, encrypted: str) -> bytes:
        """Decrypt a string and return raw bytes.

        Args:
            encrypted: Base64-encoded encrypted string.

        Returns:
            Decrypted bytes.
        """
        encrypted_bytes = base64.urlsafe_b64decode(encrypted)
        return self._fernet.decrypt(encrypted_bytes)

    def encrypt_dict(self, data: dict[str, Any]) -> str:
        """Encrypt a dictionary as JSON.

        Args:
            data: Dictionary to encrypt.

        Returns:
            Base64-encoded encrypted JSON string.
        """
        return self.encrypt(data)

    def decrypt_dict(self, encrypted: str) -> dict[str, Any]:
        """Decrypt a string and parse as JSON dictionary.

        Args:
            encrypted: Base64-encoded encrypted JSON string.

        Returns:
            Decrypted dictionary.
        """
        import json

        decrypted = self.decrypt(encrypted)
        return cast(dict[str, Any], json.loads(decrypted))


class SecretManager:
    """Environment variable and vault-based secret management.

    Provides secure access to secrets with support for:
    - Environment variables
    - Encrypted environment variables
    - File-based secrets
    - In-memory secret caching

    Attributes:
        config: Security configuration.
        _encryptor: Data encryptor for encrypted secrets.
        _cache: In-memory secret cache.
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
        import time

        if name in self._cache:
            value, expires_at = self._cache[name]
            if time.time() < expires_at:
                # Move to end (most recently used)
                self._cache_order.move_to_end(name)
                return value
            else:
                # Expired - remove
                self._cache_del(name)
        return None

    def _cache_set(self, name: str, value: str) -> None:
        """Store a secret in the cache with TTL. Evicts oldest if full."""
        import time

        expires_at = time.time() + self._cache_ttl

        # If key already exists, update it
        if name in self._cache:
            self._cache[name] = (value, expires_at)
            self._cache_order.move_to_end(name)
            return

        # Evict oldest entries if at capacity
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


class TLSConfig:
    """TLS configuration recommendations.

    Provides secure TLS settings for production deployments.

    Attributes:
        min_version: Minimum TLS version.
        ciphers: Allowed cipher suites.
    """

    RECOMMENDED_CIPHERS = (
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305"
    )

    def __init__(self, config: SecurityConfig | None = None) -> None:
        """Initialize TLS configuration.

        Args:
            config: Security configuration (optional).
        """
        if config:
            self.min_version = config.encryption.tls_min_version
            self.ciphers = config.encryption.tls_ciphers
        else:
            self.min_version = "1.2"
            self.ciphers = self.RECOMMENDED_CIPHERS

    def get_ssl_context(self) -> Any:
        """Create a secure SSL context.

        Returns:
            Configured ssl.SSLContext instance.
        """
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_versions = {
            "1.2": ssl.TLSVersion.TLSv1_2,
            "1.3": ssl.TLSVersion.TLSv1_3,
        }
        ctx.minimum_version = tls_versions.get(self.min_version, ssl.TLSVersion.TLSv1_2)
        ctx.set_ciphers(self.ciphers)
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.options |= ssl.OP_NO_RENEGOTIATION
        return ctx

    def get_mtls_server_context(
        self,
        *,
        certfile: str,
        keyfile: str,
        ca_certs: str,
    ) -> Any:
        """Create a server SSL context that requires client certificates."""
        import ssl

        ctx = self.get_ssl_context()
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ctx.load_verify_locations(cafile=ca_certs)
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def get_mtls_client_context(
        self,
        *,
        certfile: str,
        keyfile: str,
        ca_certs: str,
    ) -> Any:
        """Create a client SSL context for mutual TLS service calls."""
        import ssl

        ctx = ssl.create_default_context(cafile=ca_certs)
        ctx.minimum_version = {
            "1.2": ssl.TLSVersion.TLSv1_2,
            "1.3": ssl.TLSVersion.TLSv1_3,
        }.get(self.min_version, ssl.TLSVersion.TLSv1_2)
        ctx.set_ciphers(self.ciphers)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        return ctx

    def get_uvicorn_ssl_kwargs(self) -> dict[str, Any]:
        """Get SSL kwargs for uvicorn.

        Returns:
            Dict of SSL configuration for uvicorn.
        """
        return {
            "ssl_min_version": f"TLSv{self.min_version}",
            "ssl_ciphers": self.ciphers,
        }

    def get_uvicorn_mtls_kwargs(
        self,
        *,
        certfile: str,
        keyfile: str,
        ca_certs: str,
    ) -> dict[str, Any]:
        """Get uvicorn SSL kwargs for a server that requires client certs."""
        import ssl

        kwargs = self.get_uvicorn_ssl_kwargs()
        kwargs.update(
            {
                "ssl_certfile": certfile,
                "ssl_keyfile": keyfile,
                "ssl_ca_certs": ca_certs,
                "ssl_cert_reqs": ssl.CERT_REQUIRED,
            }
        )
        return kwargs

    def get_gunicorn_ssl_kwargs(self) -> dict[str, Any]:
        """Get SSL kwargs for gunicorn.

        Returns:
            Dict of SSL configuration for gunicorn.
        """
        return {
            "ssl_version": 5,
            "ciphers": self.ciphers,
        }
