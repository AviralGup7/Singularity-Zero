"""Tests for AEVE's bridge to ``src.exploitation.engines``.

Covers:
* Opt-in delegation is disabled by default (legacy behaviour preserved).
* ``enable_engine_delegation=True`` invokes the registered
  :class:`SafeExploiter` and translates ``ExploitResult`` fields back
  onto the finding (``impact_confirmed``, ``attack_chain_progress``,
  ``rollback_performed``, ``verification_engine``).
* Categories without a registered engine fall through to the legacy
  path.
* Exceptions raised by the exploitation framework are swallowed and
  the finding degrades cleanly.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from src.execution.exploiters.aeve import (
    AEVE,
    VerificationStatus,
    engine_for_category,
    has_engine_for_category,
)


def test_category_to_engine_covers_known_categories():
    assert has_engine_for_category("ssrf")
    assert has_engine_for_category("ssti")
    assert has_engine_for_category("path_traversal")
    assert has_engine_for_category("lfi")
    assert has_engine_for_category("xss")
    assert has_engine_for_category("sqli")
    assert has_engine_for_category("cmdi")
    assert engine_for_category("SSRF") == "ssrfexploitationengine"
    assert engine_for_category("unknown_category") is None
    assert not has_engine_for_category("")


def test_aeve_engine_delegation_disabled_by_default():
    aeve = AEVE()
    assert aeve.enable_engine_delegation is False


def test_aeve_engine_delegation_can_be_enabled():
    aeve = AEVE(enable_engine_delegation=True)
    assert aeve.enable_engine_delegation is True


@pytest.mark.asyncio
async def test_engine_delegation_translates_success_into_verified_tp():
    aeve = AEVE(use_wasm_sandbox=False, enable_engine_delegation=True)

    from src.exploitation.models import ExploitResult, ExploitStatus, ExploitTarget

    target = ExploitTarget(url="https://example.com/proxy")
    engine_result = ExploitResult(
        target=target,
        status=ExploitStatus.SUCCESS,
        engine="ssrfexploitationengine",
        risk_confirmed=True,
        rollback_performed=True,
        proof={"callback_received": True},
        evidence=["[https://example.com/proxy] SSRF callback received"],
        impact_summary="Cloud metadata endpoint reachable via user-supplied URL.",
        metadata={"mitre_techniques": ["T1189", "T1046"]},
    )
    engine_result.mark_complete()

    finding = {
        "id": "f-ssrf-1",
        "category": "ssrf",
        "url": "https://example.com/proxy?url=http://169.254.169.254/",
        "severity": "high",
        "request_context": {
            "method": "GET",
            "parameter": "url",
            "variant": "http://169.254.169.254/",
        },
    }

    async def fake_execute(self, engine_key, target):
        return engine_result

    with patch.object(
        __import__("src.exploitation.engines", fromlist=["SafeExploiter"]).SafeExploiter,
        "execute",
        new=fake_execute,
    ):
        result = await aeve.verify_finding(finding, timeout_seconds=5.0)

    assert result["verification_status"] == VerificationStatus.VERIFIED_TP.value
    assert result["impact_confirmed"] is True
    assert result["attack_chain_progress"] == ["T1189", "T1046"]
    assert result["rollback_performed"] is True
    assert result["verification_engine"] == "ssrfexploitationengine"
    assert result["confidence"] == 1.0


@pytest.mark.asyncio
async def test_engine_delegation_translates_blocked_into_candidate():
    aeve = AEVE(use_wasm_sandbox=False, enable_engine_delegation=True)

    from src.exploitation.models import ExploitResult, ExploitStatus, ExploitTarget

    target = ExploitTarget(url="https://example.com/sqli")
    engine_result = ExploitResult(
        target=target,
        status=ExploitStatus.BLOCKED,
        engine="injectionengine",
        risk_confirmed=False,
        metadata={"vuln_type": "sqli"},
    )
    engine_result.mark_complete()

    finding = {
        "id": "f-sqli-1",
        "category": "sqli",
        "url": "https://example.com/sqli",
        "request_context": {"method": "POST", "parameter": "q", "variant": "' OR '1'='1"},
    }

    async def fake_execute(self, engine_key, target):
        return engine_result

    with patch.object(
        __import__("src.exploitation.engines", fromlist=["SafeExploiter"]).SafeExploiter,
        "execute",
        new=fake_execute,
    ):
        result = await aeve.verify_finding(finding, timeout_seconds=5.0)

    assert result["verification_status"] == VerificationStatus.CANDIDATE.value
    assert result["impact_confirmed"] is False
    assert result["verification_engine"] == "injectionengine"


@pytest.mark.asyncio
async def test_engine_delegation_falls_back_when_framework_raises():
    aeve = AEVE(use_wasm_sandbox=True, enable_engine_delegation=True)

    finding = {
        "id": "f-ssrf-2",
        "category": "ssrf",
        "url": "https://example.com/proxy?url=http://169.254.169.254/",
        "request_context": {"parameter": "url", "variant": "http://169.254.169.254/"},
    }

    async def boom(self, engine_key, target):
        raise RuntimeError("SSRF check failed")

    with patch.object(
        __import__("src.exploitation.engines", fromlist=["SafeExploiter"]).SafeExploiter,
        "execute",
        new=boom,
    ):
        result = await aeve.verify_finding(finding, timeout_seconds=5.0)

    # Framework raised -> delegation returned None -> lifecycle fell
    # through to the simulation path, which succeeds for a finding with
    # a populated proof_bundle.
    assert result["verification_status"] == VerificationStatus.VERIFIED_TP.value


@pytest.mark.asyncio
async def test_engine_delegation_skipped_for_unmapped_category():
    aeve = AEVE(use_wasm_sandbox=False, enable_engine_delegation=True)

    finding = {
        "id": "f-idor-1",
        "category": "idor",
        "url": "https://api.example.com/user/123",
        "signals": ["cross_user_data_leak"],
    }

    result = await aeve.verify_finding(finding, timeout_seconds=5.0)
    assert result["verification_status"] == VerificationStatus.VERIFIED_TP.value
    assert "verification_engine" not in result


@pytest.mark.asyncio
async def test_legacy_signal_path_unaffected_by_delegation_flag():
    aeve = AEVE(use_wasm_sandbox=False, enable_engine_delegation=False)
    finding = {
        "id": "vuln-1",
        "category": "idor",
        "signals": ["cross_user_data_leak"],
        "url": "https://api.example.com/user/123",
    }
    result = await aeve.verify_finding(finding, timeout_seconds=5.0)
    assert result["verification_status"] == VerificationStatus.VERIFIED_TP.value
    assert result["confidence"] == 1.0


def test_default_aeve_has_buildable_config():
    aeve = AEVE()
    assert aeve.config is not None
    assert aeve.config.http_timeout_seconds == 10


@pytest.mark.asyncio
async def test_engine_delegation_returns_none_for_missing_url():
    aeve = AEVE(use_wasm_sandbox=False, enable_engine_delegation=True)
    outcome = await aeve._delegate_to_engine(
        "ssrfexploitationengine",
        {"id": "f-no-url", "category": "ssrf"},
    )
    assert outcome is None


if __name__ == "__main__":
    asyncio.run(pytest.main([__file__, "-v"]))
