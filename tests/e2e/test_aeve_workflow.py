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


@pytest.mark.asyncio
async def test_aeve_multi_stage_chaining_verification():
    aeve = AEVE(use_wasm_sandbox=True)

    # 1. Test XSS + CSRF -> Session Hijacking promotion
    csrf_finding = {
        "id": "csrf-1",
        "type": "csrf",
        "category": "csrf",
        "url": "https://example.com/transfer",
        "signals": ["missing_csrf_token"],
        "confidence": 0.8,
        "request_context": {"parameter": "csrf", "variant": "csrf_reflected"},
    }

    xss_finding = {
        "id": "xss-1",
        "type": "xss",
        "category": "xss",
        "url": "https://example.com/profile",
        "signals": ["xss_reflected"],
        "confidence": 0.7,
        "request_context": {"parameter": "xss", "variant": "<script>alert(1)</script>"},
    }

    # Verify csrf finding first, we keep it as a historical verified finding
    csrf_verified = await aeve.verify_finding(csrf_finding)
    assert csrf_verified["verification_status"] == VerificationStatus.VERIFIED_TP.value

    # Now verify xss finding, passing csrf_verified in historical_findings
    xss_verified = await aeve.verify_finding(xss_finding, historical_findings=[csrf_verified])

    # It should be promoted to critical severity, 1.0 confidence, and compound_status
    assert xss_verified["verification_status"] == VerificationStatus.VERIFIED_TP.value
    assert xss_verified["severity"] == "critical"
    assert xss_verified["confidence"] == 1.0
    assert xss_verified["compound_status"] == "XSS leads to Session Hijacking"

    # 2. Test IDOR + Info Disclosure -> Data Breach promotion
    info_finding = {
        "id": "info-1",
        "type": "information_disclosure",
        "category": "exposure",
        "url": "https://example.com/debug.log",
        "signals": ["sensitive_key_exposure"],
        "confidence": 0.8,
        "request_context": {"parameter": "info", "variant": "exposure"},
    }

    idor_finding = {
        "id": "idor-1",
        "type": "idor",
        "category": "idor",
        "url": "https://example.com/user/edit",
        "signals": ["cross_user_data_leak"],
        "confidence": 0.7,
        "request_context": {"parameter": "idor", "variant": "idor"},
    }

    info_verified = await aeve.verify_finding(info_finding)
    assert info_verified["verification_status"] == VerificationStatus.VERIFIED_TP.value

    idor_verified = await aeve.verify_finding(idor_finding, historical_findings=[info_verified])
    assert idor_verified["verification_status"] == VerificationStatus.VERIFIED_TP.value
    assert idor_verified["severity"] == "critical"
    assert idor_verified["confidence"] == 1.0
    assert idor_verified["compound_status"] == "IDOR leads to Data Breach"
