import pytest

from src.execution.exploiters.aeve import AEVE, VerificationStatus


@pytest.mark.asyncio
async def test_aeve_verification_lifecycle():
    aeve = AEVE(use_wasm_sandbox=False)

    # 1. Test Signal-based verification (IDOR)
    finding = {
        "id": "vuln-1",
        "category": "idor",
        "signals": ["cross_user_data_leak"],
        "url": "https://api.example.com/user/123",
        "confidence": 0.7,
    }

    verified = await aeve.verify_finding(finding)
    assert verified["verification_status"] == VerificationStatus.VERIFIED_TP.value
    assert verified["confidence"] == 1.0


@pytest.mark.asyncio
async def test_aeve_attack_chain_discovery():
    aeve = AEVE()

    # Mock findings that should be chained
    findings = [
        {
            "id": "f1",
            "type": "information_disclosure",
            "category": "exposure",
            "url": "https://example.com/config.php",
            "verification_status": VerificationStatus.VERIFIED_TP.value,
        },
        {
            "id": "f2",
            "type": "auth_bypass",
            "category": "auth",
            "url": "https://example.com/admin",
            "verification_status": VerificationStatus.VERIFIED_TP.value,
        },
    ]

    chains = aeve.discover_attack_chains(findings)
    assert len(chains) > 0
    assert "Account Takeover" in chains[0]["name"]
    assert chains[0]["steps"] == ["f1", "f2"]
    assert chains[0]["is_verified"] is True


@pytest.mark.asyncio
async def test_aeve_sandbox_simulation():
    aeve = AEVE(use_wasm_sandbox=True)

    # Finding that needs sandbox verification
    finding = {
        "id": "vuln-2",
        "category": "ssrf",
        "url": "https://example.com/proxy?url=http://169.254.169.254/latest/meta-data/",
        "request_context": {"parameter": "url", "variant": "http://169.254.169.254/"},
    }

    verified = await aeve.verify_finding(finding)
    assert verified["verification_status"] == VerificationStatus.VERIFIED_TP.value
