import json

import pytest

from src.infrastructure.frontier.vault import CyberVault, TargetSecretStore, VaultRotationPolicy
from src.infrastructure.security.encryption import Argon2idParameters

FAST_KDF = Argon2idParameters(time_cost=1, memory_cost=8192, parallelism=1)


def test_target_secret_store_encrypts_leases_and_sealed_bundle_roundtrip():
    vault = CyberVault("strong passphrase", kdf_params=FAST_KDF)
    store = TargetSecretStore(vault)

    store.set_secret("target-a", "api_key", "sk-live-secret")
    raw = store.to_dict()["target-a:api_key"]

    assert raw.startswith("csp-a256gcm-argon2id-v1:")
    assert "sk-live-secret" not in raw

    with store.lease_secret("target-a", "api_key") as lease:
        assert lease.text == "sk-live-secret"
        buf = lease.expose_bytearray()
    assert set(buf) == {0}

    bundle = store.export_sealed_bundle("offline runner key")
    assert "sk-live-secret" not in bundle
    parsed = json.loads(bundle)
    assert parsed["magic"] == "CSP_SEALED_BUNDLE"
    assert parsed["manifest_sha256"]

    restored = TargetSecretStore(CyberVault("strong passphrase", kdf_params=FAST_KDF))
    restored.import_sealed_bundle(bundle, "offline runner key")
    assert restored.get_secret("target-a", "api_key") == "sk-live-secret"


def test_vault_auto_rotation_reencrypts_records():
    vault = CyberVault(
        "strong passphrase",
        rotation_policy=VaultRotationPolicy(interval_seconds=0),
        kdf_params=FAST_KDF,
    )
    store = TargetSecretStore(vault)

    store.set_secret("target-a", "token", "first")
    first_envelope = store.to_dict()["target-a:token"]
    store.set_secret("target-b", "token", "second")

    assert vault.key_version > 1
    assert store.to_dict()["target-a:token"] != first_envelope
    assert store.get_secret("target-a", "token") == "first"
    assert store.get_secret("target-b", "token") == "second"


def test_missing_secret_lease_raises_key_error():
    store = TargetSecretStore(CyberVault("strong passphrase", kdf_params=FAST_KDF))
    with pytest.raises(KeyError):
        with store.lease_secret("missing", "api_key"):
            pass
