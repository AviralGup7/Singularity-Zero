import asyncio
from unittest.mock import MagicMock

import pytest

from src.execution.active_manifest import get_active_manifest, reset_active_manifest_registry
from src.execution.exploiters.aeve import AEVE, VerificationStatus
from src.execution.exploiters.payload_integrity import ExploitPayloadValidator
from src.execution.remediators.remediation_scanner import RemediationScanner


def test_payload_integrity_json_import_fix():
    payload = {"command": "whoami"}
    safe, msg = ExploitPayloadValidator.is_safe_payload(payload)
    assert safe is True
    assert "Payload verified as compliant" in msg


@pytest.mark.asyncio
async def test_aeve_timeout_graceful_degradation():
    aeve = AEVE(use_wasm_sandbox=False)

    # Mock validation lifecycle to sleep indefinitely
    async def mock_validation(finding):
        await asyncio.sleep(10.0)
        return True

    aeve._execute_validation_lifecycle = mock_validation
    finding = {"category": "xss", "id": "test_xss_timeout"}

    # Run with small timeout of 0.05 seconds
    result = await aeve.verify_finding(finding, timeout_seconds=0.05)
    assert result["verification_status"] == VerificationStatus.DEGRADED.value


@pytest.mark.asyncio
async def test_remediation_scanner_redis_failure():
    scanner = RemediationScanner(use_wasm_sandbox=False)
    redis_mock = MagicMock()
    # Mock execute_command to raise an exception
    redis_mock.execute_command.side_effect = Exception("Connection lost")

    finding = {"id": "1234", "target": "https://example.com"}

    # Scanner should raise RuntimeError (fail fast) rather than silently bypassing cooldown
    with pytest.raises(RuntimeError) as exc:
        await scanner.verify_remediation(finding, redis_client=redis_mock)
    assert "Database error" in str(exc.value)


def test_active_manifest_registry_reset():
    manifest = get_active_manifest("xss")
    assert manifest is not None

    # Reset registry
    reset_active_manifest_registry()
    manifest_after = get_active_manifest("xss")
    assert manifest_after is not None
