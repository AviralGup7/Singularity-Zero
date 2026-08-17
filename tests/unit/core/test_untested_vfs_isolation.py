"""Coverage for Ghost-VFS isolation policy (no invented crypto)."""

from __future__ import annotations

import pytest

from src.core.frontier.vfs_isolation import (
    HardwareEnclaveProvider,
    VFSEncryptionPolicy,
)


@pytest.mark.unit
def test_policy_restricts_secrets_and_unknown_roles() -> None:
    policy = VFSEncryptionPolicy()
    assert policy.is_allowed("analyst", "read", "reports/a.json") is True
    assert policy.is_allowed("analyst", "write", "reports/a.json") is False
    assert policy.is_allowed("analyst", "read", "vault/secrets/token") is False
    assert policy.is_allowed("admin", "read", "vault/secrets/token") is True
    assert policy.is_allowed("system", "read", "certs/server.pem") is True
    assert policy.is_allowed("audit", "read", "certs/server.pem") is False
    assert policy.is_allowed("nobody", "read", "reports/a.json") is False


@pytest.mark.unit
def test_enclave_stub_is_identity() -> None:
    assert HardwareEnclaveProvider.is_available() is False
    assert HardwareEnclaveProvider.seal_data(b"abc") == b"abc"
    assert HardwareEnclaveProvider.unseal_data(b"abc") == b"abc"
