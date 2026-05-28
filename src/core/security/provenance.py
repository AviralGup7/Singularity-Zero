"""Nuclei template provenance verification using Ed25519 signature and SHA-256 hashes.

Ensures that before running any Nuclei template in the security test pipeline,
its hash is verified against a signed manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# Default trusted high-entropy public key for local development
# Generate a new pair in production and configure NUCLEI_SIGNATURE_PUBLIC_KEY
DEFAULT_TRUSTED_PUBKEY = "8c6f1406e2cf6fb4ef1e97d191d8481dfb152d1136c1e550e6ee693b7df0898c"


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

    # Load trusted public key
    pubkey_hex = os.getenv("NUCLEI_SIGNATURE_PUBLIC_KEY", DEFAULT_TRUSTED_PUBKEY)
    try:
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
        template_rel_path = str(Path(template_path).resolve().relative_to(manifest_dir.resolve())).replace(
            "\\", "/"
        )
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
