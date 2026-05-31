"""Encryption utilities for the Cyber Security Test Pipeline.

Provides data-at-rest encryption, API key encryption, TLS configuration
recommendations, and secret management utilities.
"""

from __future__ import annotations

import base64
import os
from typing import Any, cast

from src.core.logging.trace_logging import get_pipeline_logger

# Re-exports of modular sub-components for backwards compatibility
from src.infrastructure.security.argon2id_aesgcm import (
    Argon2idAESGCM,
    Argon2idParameters,
    SecretLease,
    secure_wipe,
)
from src.infrastructure.security.sealed_bundle import (
    sealed_bundle_decrypt,
    sealed_bundle_encrypt,
)
from src.infrastructure.security.secret_manager import SecretManager
from src.infrastructure.security.tls_config import TLSConfig

__all__ = [
    "Argon2idAESGCM",
    "Argon2idParameters",
    "SecretLease",
    "secure_wipe",
    "sealed_bundle_decrypt",
    "sealed_bundle_encrypt",
    "TLSConfig",
    "SecretManager",
    "generate_fernet_key",
    "encrypt_data",
    "decrypt_data",
    "encrypt_string",
    "decrypt_string",
    "redis_tls_kwargs_from_env",
    "DataEncryptor",
]

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
