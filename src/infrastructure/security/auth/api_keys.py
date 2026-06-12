"""API key generation, validation, rotation, and revocation."""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from src.infrastructure.security.config import SecurityConfig
from src.infrastructure.security.encryption import sealed_bundle_decrypt, sealed_bundle_encrypt

from .models import APIKey, Role

logger = logging.getLogger(__name__)


class _AuditSink(Protocol):
    def log(self, *args: Any, **kwargs: Any) -> Any: ...


def generate_api_key(config: SecurityConfig) -> str:
    """Generate a raw API key string with the configured prefix.

    Args:
        config: Security configuration containing the key prefix.

    Returns:
        Raw API key string (prefix + random hex).
    """
    return config.api_key.key_prefix + secrets.token_hex(32)


def hash_api_key(raw_key: str, pepper: str | None = None) -> str:
    """Compute HMAC-SHA256 hash of an API key with a server-side pepper.

    Uses HMAC-SHA256 with an optional pepper (server-side secret) to
    prevent offline brute-force/rainbow-table attacks even if the stored
    hashes are compromised. The pepper MUST be stored separately from
    the hash database (e.g., in a vault or environment variable).

    Args:
        raw_key: Raw API key string.
        pepper: Server-side secret pepper. If None, the
            SEC_API_KEY_PEPPER environment variable is used. If that
            is also unset, a per-process random pepper is generated
            (non-persistent; suitable only for single-process testing).

    Returns:
        Hex-encoded HMAC-SHA256 hash.
    """
    effective_pepper = pepper or os.environ.get("SEC_API_KEY_PEPPER", "")
    if not effective_pepper:
        # Per-process random pepper — NOT suitable for production with
        # multiple processes. Log a warning so operators know.
        logger.warning(
            "No SEC_API_KEY_PEPPER set; using per-process random pepper. "
            "API key hashes will not survive restarts. "
            "Set SEC_API_KEY_PEPPER for durable production hashing."
        )
        effective_pepper = hashlib.sha256(os.urandom(32)).hexdigest()
    return hmac.new(
        effective_pepper.encode("utf-8"),
        raw_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class APIKeyStore:
    """In-memory store and lifecycle manager for API keys.

    Attributes:
        config: Security configuration.
        _api_keys: Dict mapping key_hash -> APIKey.
        _user_api_keys: Dict mapping user_id -> list of key hashes.
    """

    def __init__(
        self,
        config: SecurityConfig,
        audit_logger: _AuditSink | None = None,
        pepper: str | None = None,
    ) -> None:
        """Initialize the API key store.

        Args:
            config: Security configuration.
            pepper: Server-side pepper for HMAC-SHA256 key hashing.
                If None, falls back to SEC_API_KEY_PEPPER env var.
        """
        self.config = config
        self._api_keys: dict[str, APIKey] = {}
        self._user_api_keys: dict[str, list[str]] = {}
        self._audit_logger = audit_logger
        # Stabilise pepper: use the provided pepper, fall back to the env
        # var, or generate a deterministic per-instance pepper so that
        # create/validate calls within the same process always agree.
        if pepper is not None:
            self._pepper = pepper
        else:
            env_pepper = os.environ.get("SEC_API_KEY_PEPPER", "")
            if env_pepper:
                self._pepper = env_pepper
            else:
                self._pepper = hashlib.sha256(os.urandom(32)).hexdigest()
        # Rate limiting for validate() to prevent brute-force attacks.
        # Maps raw_key_hash -> (attempt_count, window_start).
        self._validate_attempts: dict[str, tuple[int, float]] = {}
        self._validate_lock = threading.Lock()
        self._max_validate_attempts = 10
        self._validate_window_seconds = 60.0

    def _audit(
        self, event: str, user_id: str | None = None, key_id: str | None = None, **details: Any
    ) -> None:
        if self._audit_logger is None:
            return
        try:
            self._audit_logger.log(
                event=event,
                user_id=user_id,
                resource_id=key_id,
                details=details,
            )
        except Exception as exc:
            logger.warning("Audit log failed for %s: %s", event, exc)

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
        key_hash = hash_api_key(raw_key, pepper=self._pepper)
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
        self._audit("apikey.create", user_id=user_id, key_id=api_key.id, key_prefix=key_prefix)

        return raw_key, api_key

    def validate(self, raw_key: str) -> APIKey | None:
        """Validate an API key and return its model if valid.

        Includes rate-limiting: after N failed attempts within a
        time window, the key is temporarily rejected to slow down
        brute-force attacks.

        Args:
            raw_key: Raw API key string.

        Returns:
            APIKey if valid, None otherwise.
        """
        key_hash = hash_api_key(raw_key, pepper=self._pepper)

        # Rate-limiting check
        now = time.time()
        with self._validate_lock:
            attempt_info = self._validate_attempts.get(key_hash)
            if attempt_info is not None:
                count, window_start = attempt_info
                if now - window_start < self._validate_window_seconds:
                    if count >= self._max_validate_attempts:
                        self._audit("apikey.access", result="rate_limited")
                        return None
                else:
                    # Reset window
                    self._validate_attempts[key_hash] = (0, now)
            else:
                self._validate_attempts[key_hash] = (0, now)

        api_key = self._api_keys.get(key_hash)

        if api_key is None or not api_key.is_valid:
            # Increment failed attempt counter
            with self._validate_lock:
                attempt_info = self._validate_attempts.get(key_hash)
                if attempt_info is not None:
                    count, window_start = attempt_info
                    if now - window_start < self._validate_window_seconds:
                        self._validate_attempts[key_hash] = (count + 1, window_start)
                    else:
                        self._validate_attempts[key_hash] = (1, now)
                else:
                    self._validate_attempts[key_hash] = (1, now)
            self._audit("apikey.access", result="denied")
            return None

        # Reset rate limiter on successful validation
        with self._validate_lock:
            self._validate_attempts.pop(key_hash, None)

        api_key.last_used_at = datetime.now(UTC).timestamp()
        self._audit(
            "apikey.access",
            user_id=api_key.user_id,
            key_id=api_key.id,
            key_prefix=api_key.key_prefix,
            result="success",
        )
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
        self._audit(
            "apikey.rotate", user_id=old_key.user_id, key_id=old_key.id, new_key_id=new_key.id
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
                self._audit("apikey.revoke", user_id=api_key.user_id, key_id=api_key.id)
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

    def export_sealed_bundle(self, passphrase: str, *, name: str = "api-key-store") -> str:
        """Export stored API key metadata in a sealed Argon2id/AES-GCM bundle."""
        records = {
            "api_keys": {
                key_hash: key.model_dump(mode="json") for key_hash, key in self._api_keys.items()
            },
            "user_api_keys": self._user_api_keys,
        }
        self._audit("credential.bundle_export", secret_count=len(self._api_keys), bundle_name=name)
        return cast(
            str, sealed_bundle_encrypt(name, records, passphrase, aad=b"csp:auth:api-key-store")
        )

    def import_sealed_bundle(self, bundle: str | bytes, passphrase: str) -> None:
        """Restore API key metadata from a sealed bundle.

        Raises:
            ValueError: If the bundle is tampered or passphrase is wrong.
        """
        try:
            payload = sealed_bundle_decrypt(bundle, passphrase, aad=b"csp:auth:api-key-store")
        except Exception as exc:
            logger.error("Failed to decrypt/import sealed bundle: %s", exc)
            raise
        records = payload["records"]
        raw_keys = json.loads(json.dumps(records.get("api_keys", {})))
        self._api_keys = {
            key_hash: APIKey.model_validate(value) for key_hash, value in raw_keys.items()
        }
        self._user_api_keys = {
            str(user_id): [str(item) for item in values]
            for user_id, values in records.get("user_api_keys", {}).items()
        }
        self._audit("credential.bundle_import", secret_count=len(self._api_keys))
