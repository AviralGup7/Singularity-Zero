"""Nuclei template provenance verification using Ed25519 signature and SHA-256 hashes.

Ensures that before running any Nuclei template in the security test pipeline,
its hash is verified against a signed manifest.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger(__name__)

# Environment that requires an explicit, non-default public key.
_PROD_ENVIRONMENTS = frozenset({"production", "prod", "staging", "stage"})

# Dev-only public key, intentionally retained for local development.
# Production deployments MUST set NUCLEI_SIGNATURE_PUBLIC_KEY to a key
# they generated themselves. A bare dev key in production would allow
# an attacker who can sign templates with the corresponding private
# key (which is checked into this public repository) to inject
# arbitrary Nuclei templates.
DEFAULT_DEV_TRUSTED_PUBKEY = "8c6f1406e2cf6fb4ef1e97d191d8481dfb152d1136c1e550e6ee693b7df0898c"


def _resolve_environment() -> str:
    """Best-effort detection of the current runtime environment."""
    for var in ("APP_ENV", "ENVIRONMENT", "ENV", "PIPELINE_ENV"):
        raw = os.getenv(var)
        if raw:
            return raw.strip().lower()
    return ""


def _resolve_trusted_pubkey() -> str:
    """Return the public key to trust, refusing the dev default in prod."""
    pubkey_hex = os.getenv("NUCLEI_SIGNATURE_PUBLIC_KEY")
    if pubkey_hex:
        return pubkey_hex.strip()
    # Bug #12 fix: previously the function only refused the dev key when
    # the resolved environment was in ``_PROD_ENVIRONMENTS``. Any other
    # value (including an unset/empty environment, ``"qa"``, ``"staging"``
    # misconfigured, or a typo) silently fell through to the embedded
    # development key, whose private counterpart is in this public repo.
    # We now require *both* the env to be an explicitly dev-allow-listed
    # value AND ``APP_SECURITY_PERMISSIVE=1`` to use the dev key;
    # otherwise we refuse to verify.
    env = _resolve_environment()
    if env not in _DEV_ALLOWED_ENVIRONMENTS:
        raise ValueError(
            "Provenance Error: NUCLEI_SIGNATURE_PUBLIC_KEY is required outside "
            "of explicitly allow-listed dev environments "
            f"(env={env!r}, allowed={sorted(_DEV_ALLOWED_ENVIRONMENTS)}); "
            "refusing to fall back to the embedded development key."
        )
    if os.environ.get("APP_SECURITY_PERMISSIVE", "").strip().lower() not in {"1", "true", "yes"}:
        raise ValueError(
            "Provenance Error: dev public key may only be used when "
            "APP_SECURITY_PERMISSIVE=1 is set explicitly."
        )
    logger.warning(
        "Provenance: using embedded development public key. Set "
        "NUCLEI_SIGNATURE_PUBLIC_KEY before any non-development use."
    )
    return DEFAULT_DEV_TRUSTED_PUBKEY


# Bug #12 fix: hard-coded allow-list of environments that may use the
# embedded dev key, mirroring ``secret_validator._is_dev_environment``.
_DEV_ALLOWED_ENVIRONMENTS = frozenset({"dev", "development", "local", "test"})


def verify_provenance(template_path: str | Path, manifest_dir: str | Path) -> bool:
    """Verify that a Nuclei template matches its signed SHA-256 manifest.

    Args:
        template_path: Absolute or relative path to the template file to check.
        manifest_dir: The directory containing `manifest.json` and `manifest.json.sig`.

    Returns:
        True if verification succeeds.

    Raises:
        ValueError: If the manifest is missing, signature is invalid, or template
                    hash mismatch is detected (provenance/integrity failure).
    """
    manifest_dir = Path(manifest_dir)
    manifest_path = manifest_dir / "manifest.json"
    signature_path = manifest_dir / "manifest.json.sig"

    if not manifest_path.exists() or not signature_path.exists():
        raise ValueError(
            f"Provenance Error: Missing signed manifest for directory '{manifest_dir}'"
        )

    # Read manifest and signature
    manifest_bytes = manifest_path.read_bytes()
    sig_hex = signature_path.read_text(encoding="utf-8").strip()
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise ValueError("Provenance Error: Invalid signature format (must be hex)") from exc

    # Load trusted public key (refuses dev default in production).
    try:
        pubkey_hex = _resolve_trusted_pubkey()
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    except Exception as exc:
        raise ValueError(f"Provenance Error: Invalid trusted public key: {exc}") from exc

    # Verify signature
    try:
        public_key.verify(sig_bytes, manifest_bytes)
    except InvalidSignature as exc:
        raise ValueError("Provenance Error: Manifest signature verification failed!") from exc

    # Load manifest data
    try:
        manifest_data = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Provenance Error: Failed to parse manifest JSON: {exc}") from exc

    # Calculate relative template path to compare with manifest entries
    try:
        template_rel_path = str(
            Path(template_path).resolve().relative_to(manifest_dir.resolve())
        ).replace("\\", "/")
    except ValueError:
        # Fallback if path is not relative to manifest_dir
        template_rel_path = Path(template_path).name.replace("\\", "/")

    expected_hash = manifest_data.get("templates", {}).get(template_rel_path)
    if not expected_hash:
        raise ValueError(
            f"Provenance Error: Template '{template_rel_path}' is not registered in the signed manifest!"
        )

    # Calculate actual SHA-256 of the template file
    sha256 = hashlib.sha256()
    with open(template_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    actual_hash = sha256.hexdigest()

    if actual_hash != expected_hash:
        raise ValueError(
            f"Provenance Error: Hash mismatch for '{template_rel_path}'! "
            f"Expected {expected_hash}, got {actual_hash}"
        )

    return True
