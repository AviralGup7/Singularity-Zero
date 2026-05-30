"""Sealed integrity-bound JSON bundles for offline runners."""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
from datetime import UTC, datetime
from typing import Any, cast

from src.infrastructure.security.argon2id_aesgcm import Argon2idAESGCM, Argon2idParameters


def sealed_bundle_encrypt(
    name: str,
    records: dict[str, Any],
    passphrase: str,
    *,
    aad: bytes | None = None,
    params: Argon2idParameters | None = None,
) -> str:
    """Create a sealed, integrity-bound JSON bundle for offline runners."""
    canonical_records = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest = {
        "name": name,
        "created_at": datetime.now(UTC).isoformat(),
        "record_count": len(records),
        "records_sha256": hashlib.sha256(canonical_records).hexdigest(),
    }
    payload = {"manifest": manifest, "records": records}
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope = Argon2idAESGCM(passphrase, params).encrypt(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        aad=aad or manifest_bytes,
    )
    bundle = {
        "magic": "CSP_SEALED_BUNDLE",
        "version": 1,
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "envelope": envelope,
    }
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"))


def sealed_bundle_decrypt(
    bundle: str | bytes,
    passphrase: str,
    *,
    aad: bytes | None = None,
) -> dict[str, Any]:
    """Open and verify a sealed bundle created by sealed_bundle_encrypt."""
    raw = bundle.decode("utf-8") if isinstance(bundle, bytes) else bundle
    data = json.loads(raw)
    if data.get("magic") != "CSP_SEALED_BUNDLE" or data.get("version") != 1:
        raise ValueError("unsupported sealed bundle")
    manifest = cast(dict[str, Any], data["manifest"])
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac_module.compare_digest(expected_manifest_hash, cast(str, data["manifest_sha256"])):
        raise ValueError("sealed bundle manifest integrity check failed")

    plaintext = Argon2idAESGCM(passphrase).decrypt(
        cast(str, data["envelope"]), aad=aad or manifest_bytes
    )
    payload = json.loads(plaintext.decode("utf-8"))
    records = cast(dict[str, Any], payload["records"])
    canonical_records = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_records_hash = hashlib.sha256(canonical_records).hexdigest()
    if not hmac_module.compare_digest(expected_records_hash, cast(str, manifest["records_sha256"])):
        raise ValueError("sealed bundle record integrity check failed")
    return cast(dict[str, Any], payload)
