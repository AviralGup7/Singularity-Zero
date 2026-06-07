"""Tests for the modern risk domain modules.

Covers:

* ``AssetRegistry`` and ``AssetCriticalityService``
* ``BusinessContext`` and ``BusinessContextConfig``
* ``CompensatingControlEngine`` and the 0.05 discount floor
* ``RiskAcceptanceManager`` and the suppression factor
* ``FindingLifecycleManager`` (state transitions, per-stage lag)
* ``RemediationPriorityCalculator`` (composite, reasons)
* ``ModernRiskCalculator`` (multi-dimensional composite)
* ``CVSSv4Score`` (alongside legacy v3.1)
* ``EPSSClient`` / ``CISAKEVClient`` test-mode / cache behavior
"""

from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

from src.intelligence.risk.asset_registry import (
    Asset,
    AssetContext,
    AssetCriticalityService,
    AssetRegistry,
    KNOWN_ASSET_TYPES,
)
from src.intelligence.risk.business_context import (
    BusinessContext,
    BusinessContextConfig,
)
from src.intelligence.risk.compensating_controls import (
    CompensatingControl,
    CompensatingControlEngine,
)
from src.intelligence.risk.finding_lifecycle import (
    DEFAULT_TRIAGE_SLA_DAYS,
    DEFAULT_VERIFICATION_SLA_DAYS,
    FindingLifecycleManager,
    FindingState,
    can_transition,
)
from src.intelligence.risk.modern_risk import (
    ModernRiskCalculator,
    ModernRiskInputs,
    ModernRiskScore,
)
from src.intelligence.risk.remediation_priority import (
    PriorityWeights,
    RemediationPriorityCalculator,
)
from src.intelligence.risk.risk_acceptance import (
    ACCEPTANCE_SCOPE_GLOBAL,
    ACCEPTANCE_STATE_ACTIVE,
    ACCEPTANCE_SUPPRESSION_FACTOR,
    RiskAcceptance,
    RiskAcceptanceManager,
)


# ---------------------------------------------------------------------------
# Asset registry / criticality
# ---------------------------------------------------------------------------


class TestAssetRegistry(unittest.TestCase):
    def test_register_and_lookup(self) -> None:
        registry = AssetRegistry()
        registry.add(
            Asset(
                asset_id="asset-payments",
                name="Payments API",
                host_pattern="*.payments.example.com",
                asset_type="payment_processor",
                criticality=1.5,
            )
        )
        match = registry.lookup("https://api.payments.example.com/charge")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.asset_id, "asset-payments")

    def test_match_returns_none_for_unknown_host(self) -> None:
        registry = AssetRegistry()
        registry.add(
            Asset(
                asset_id="asset-payments",
                name="Payments",
                host_pattern="*.payments.example.com",
                asset_type="payment_processor",
                criticality=1.5,
            )
        )
        self.assertIsNone(registry.lookup("https://marketing.example.com/"))

    def test_criticality_uplift(self) -> None:
        registry = AssetRegistry()
        registry.add(
            Asset(
                asset_id="a1",
                name="Marketing",
                host_pattern="*.marketing.example.com",
                asset_type="marketing_site",
                criticality=0.8,
            )
        )
        registry.add(
            Asset(
                asset_id="a2",
                name="Payments",
                host_pattern="*.payments.example.com",
                asset_type="payment_processor",
                criticality=1.5,
            )
        )
        service = AssetCriticalityService(registry=registry)
        ctx = service.resolve("https://api.payments.example.com/charge")
        self.assertIsNotNone(ctx.asset)
        self.assertGreater(ctx.criticality_score, 1.0)

    def test_known_asset_types_non_empty(self) -> None:
        self.assertGreater(len(KNOWN_ASSET_TYPES), 5)
        self.assertIn("payment_processor", KNOWN_ASSET_TYPES)


# ---------------------------------------------------------------------------
# Business context
# ---------------------------------------------------------------------------


class TestBusinessContext(unittest.TestCase):
    def test_multiplier_for_payment_processor(self) -> None:
        ctx = BusinessContext()
        self.assertGreater(ctx.get_entity_multiplier("payment_processor"), 1.0)

    def test_marketing_site_downgrades(self) -> None:
        ctx = BusinessContext()
        self.assertLess(ctx.get_entity_multiplier("static_site"), 1.0)
        self.assertLess(ctx.get_entity_multiplier("documentation"), 1.0)

    def test_default_multiplier_floor(self) -> None:
        ctx = BusinessContext()
        self.assertEqual(ctx.get_entity_multiplier("unknown"), 1.0)


# ---------------------------------------------------------------------------
# Compensating controls
# ---------------------------------------------------------------------------


class TestCompensatingControls(unittest.TestCase):
    def test_discount_clamped_to_floor(self) -> None:
        engine = CompensatingControlEngine()
        engine.register(
            CompensatingControl(
                control_id="c1",
                finding_id="f1",
                control_type="waf",
                discount_factor=0.0,
            )
        )
        engine.register(
            CompensatingControl(
                control_id="c2",
                finding_id="f1",
                control_type="mfa",
                discount_factor=0.0,
            )
        )
        combined = engine.combined_discount("f1")
        self.assertGreaterEqual(combined, CompensatingControlEngine.DISCOUNT_FLOOR)

    def test_no_controls_returns_one(self) -> None:
        engine = CompensatingControlEngine()
        self.assertEqual(engine.combined_discount("f1"), 1.0)

    def test_waf_discounts_severity(self) -> None:
        engine = CompensatingControlEngine()
        engine.register(
            CompensatingControl(
                control_id="c1",
                finding_id="f1",
                control_type="waf",
                discount_factor=0.20,
            )
        )
        combined = engine.combined_discount("f1")
        self.assertLess(combined, 1.0)
        self.assertGreaterEqual(combined, CompensatingControlEngine.DISCOUNT_FLOOR)


# ---------------------------------------------------------------------------
# Risk acceptance
# ---------------------------------------------------------------------------


class TestRiskAcceptanceManager(unittest.TestCase):
    def test_active_acceptance_suppresses(self) -> None:
        manager = RiskAcceptanceManager()
        manager.add(
            RiskAcceptance(
                acceptance_id="acc-1",
                finding_id="f-1",
                accepted_by="analyst@example.com",
                justification="Compensating control deployed",
                state=ACCEPTANCE_STATE_ACTIVE,
                scope=ACCEPTANCE_SCOPE_GLOBAL,
            )
        )
        factor = manager.suppression_factor("f-1")
        self.assertEqual(factor, ACCEPTANCE_SUPPRESSION_FACTOR)
        self.assertTrue(manager.evaluate_finding("f-1")["suppressed"])

    def test_revoked_acceptance_does_not_suppress(self) -> None:
        manager = RiskAcceptanceManager()
        manager.add(
            RiskAcceptance(
                acceptance_id="acc-1",
                finding_id="f-1",
                accepted_by="analyst@example.com",
                justification="",
                state=ACCEPTANCE_STATE_ACTIVE,
            )
        )
        manager.revoke("acc-1")
        factor = manager.suppression_factor("f-1")
        self.assertEqual(factor, 1.0)

    def test_other_finding_not_accepted(self) -> None:
        manager = RiskAcceptanceManager()
        factor = manager.suppression_factor("missing")
        self.assertEqual(factor, 1.0)


# ---------------------------------------------------------------------------
# Finding lifecycle
# ---------------------------------------------------------------------------


class TestFindingLifecycle(unittest.TestCase):
    def test_state_machine_allows_legal_transition(self) -> None:
        manager = FindingLifecycleManager()
        record = manager.transition("f-1", FindingState.TRIAGED)
        self.assertEqual(record.current_state, FindingState.TRIAGED)

    def test_state_machine_blocks_illegal_transition(self) -> None:
        manager = FindingLifecycleManager()
        manager.transition("f-1", FindingState.TRIAGED)
        # TRIAGED -> VERIFIED is illegal (must go via IN_REMEDIATION/FIXED).
        with self.assertRaises(ValueError):
            manager.transition("f-1", FindingState.VERIFIED)

    def test_can_transition_helper(self) -> None:
        self.assertTrue(can_transition(FindingState.OPEN, FindingState.TRIAGED))
        self.assertFalse(can_transition(FindingState.OPEN, FindingState.VERIFIED))

    def test_per_stage_lag_metrics(self) -> None:
        manager = FindingLifecycleManager()
        base = time.time()
        manager.ensure("f-1", discovered_at=base)
        manager.transition(
            "f-1", FindingState.TRIAGED, timestamp=base + DEFAULT_TRIAGE_SLA_DAYS * 86400
        )
        manager.transition(
            "f-1",
            FindingState.IN_REMEDIATION,
            timestamp=base + (DEFAULT_TRIAGE_SLA_DAYS + 1) * 86400,
        )
        manager.transition(
            "f-1",
            FindingState.FIXED,
            timestamp=base + (DEFAULT_TRIAGE_SLA_DAYS + 3) * 86400,
        )
        manager.transition(
            "f-1",
            FindingState.VERIFIED,
            timestamp=base + (DEFAULT_TRIAGE_SLA_DAYS + 3 + DEFAULT_VERIFICATION_SLA_DAYS) * 86400,
        )
        record = manager.get("f-1")
        assert record is not None
        self.assertIsNotNone(record.triage_lag_days)
        self.assertIsNotNone(record.remediation_days)
        self.assertIsNotNone(record.verification_days)

    def test_summary_aggregates_per_state(self) -> None:
        manager = FindingLifecycleManager()
        manager.transition("f-1", FindingState.TRIAGED)
        manager.transition("f-2", FindingState.TRIAGED)
        summary = manager.summary()
        self.assertEqual(summary["by_state"][FindingState.TRIAGED.value], 2)


# ---------------------------------------------------------------------------
# Remediation priority
# ---------------------------------------------------------------------------


class TestRemediationPriority(unittest.TestCase):
    def test_high_priority_finding_ranks_higher(self) -> None:
        calc = RemediationPriorityCalculator()
        high = calc.for_finding(
            {
                "id": "f-1",
                "modern_risk_score": 9.0,
                "asset_criticality_score": 1.5,
                "epss_score": 0.9,
                "attack_chain_weight": 8.0,
                "analyst_tp_rate": 0.9,
                "threat_intel": {"cisa_kev": True},
            }
        )
        low = calc.for_finding(
            {
                "id": "f-2",
                "modern_risk_score": 2.0,
                "asset_criticality_score": 0.8,
                "epss_score": 0.0,
                "attack_chain_weight": 0.0,
                "analyst_tp_rate": 0.1,
                "threat_intel": {},
            }
        )
        self.assertGreater(high.priority, low.priority)
        self.assertIn("cisa_kev", high.reason_codes)

    def test_rank_assigns_sequential_ranks(self) -> None:
        calc = RemediationPriorityCalculator()
        ranked = calc.rank_findings(
            [
                {"id": "a", "modern_risk_score": 2.0},
                {"id": "b", "modern_risk_score": 8.0},
                {"id": "c", "modern_risk_score": 5.0},
            ]
        )
        self.assertEqual([r.finding_id for r in ranked], ["b", "c", "a"])
        self.assertEqual([r.rank for r in ranked], [1, 2, 3])

    def test_priority_clamped_to_zero_hundred(self) -> None:
        calc = RemediationPriorityCalculator(weights=PriorityWeights(modern_risk=1.0))
        priority = calc.for_finding({"id": "f-1", "modern_risk_score": 5.0})
        self.assertGreaterEqual(priority.priority, 0.0)
        self.assertLessEqual(priority.priority, 100.0)


# ---------------------------------------------------------------------------
# Modern risk
# ---------------------------------------------------------------------------


class TestModernRisk(unittest.TestCase):
    def test_modern_risk_clamps_to_zero_hundred(self) -> None:
        score = ModernRiskCalculator().compute(
            ModernRiskInputs(
                cvss_v4_base=10.0,
                cvss_v4_threat_multiplier=1.5,
                epss_score=1.0,
                in_cisa_kev=True,
                asset_criticality=10.0,
                business_multiplier=2.0,
                control_discount=0.05,
                attack_chain_weight=10.0,
                chain_amplification=2.0,
                threat_actor_capability=2.0,
            )
        )
        # The score is a ModernRiskScore dataclass; check the
        # exposed attribute name.
        self.assertGreaterEqual(score.modern_risk_score, 0.0)
        self.assertLessEqual(score.modern_risk_score, 100.0)
        self.assertIsInstance(score, ModernRiskScore)

    def test_finding_modern_risk_returns_components(self) -> None:
        score = ModernRiskCalculator().for_finding(
            {
                "cvss_v4_base": 9.0,
                "asset_criticality_score": 1.4,
                "business_multiplier": 1.2,
                "control_discount": 0.9,
                "attack_chain_weight": 0.5,
                "chain_amplification": 1.0,
            }
        )
        self.assertGreater(score.modern_risk_score, 0.0)
        self.assertGreater(score.components["asset_criticality"], 0.0)


# ---------------------------------------------------------------------------
# CVSS v4 + EPSS + KEV
# ---------------------------------------------------------------------------


class TestCVSSv4AndThreatIntel(unittest.TestCase):
    def test_cvss_v4_score_returns_value(self) -> None:
        from src.intelligence.risk.cvss_v4 import score_finding_cvss_v4

        score = score_finding_cvss_v4(
            category="ssrf",
            evidence={"is_internet_facing": True, "exploit_public": True},
            epss_score=0.9,
            in_cisa_kev=True,
        )
        self.assertGreater(score.base_score, 0.0)

    def test_epss_client_lookup_offline(self) -> None:
        from src.intelligence.risk.epss import EPSSClient

        with patch.dict(
            os.environ, {"PIPELINE_OFFLINE": "1"}, clear=False
        ):
            client = EPSSClient()
            result = client.lookup("CVE-2024-1234")
            # Offline: no remote fetch, no cached result, returns None.
            self.assertIsNone(result)

    def test_cisa_kev_lookup_offline(self) -> None:
        from src.intelligence.risk.cisa_kev import CISAKEVClient

        with patch.dict(
            os.environ, {"PIPELINE_OFFLINE": "1"}, clear=False
        ):
            client = CISAKEVClient()
            self.assertFalse(client.is_known_exploited("CVE-2024-1234"))


# ---------------------------------------------------------------------------
# threat_intel module test_mode behavior
# ---------------------------------------------------------------------------


class TestThreatIntelModuleTestMode(unittest.TestCase):
    def test_threat_intel_uses_env_var(self) -> None:
        from src.intelligence import threat_intel

        with patch.dict(
            os.environ, {"PIPELINE_THREAT_INTEL_TEST_MODE": "1"}, clear=False
        ):
            self.assertTrue(threat_intel._is_test_mode())

        with patch.dict(
            os.environ, {"PIPELINE_THREAT_INTEL_TEST_MODE": "0"}, clear=False
        ):
            self.assertFalse(threat_intel._is_test_mode())

    def test_threat_intel_does_not_use_sys_modules(self) -> None:
        from src.intelligence import threat_intel

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("PIPELINE_THREAT_INTEL_TEST_MODE", None)
            # Even if pytest is in sys.modules (which it is during
            # tests), threat_intel should NOT activate test mode
            # just because of that.
            self.assertFalse(threat_intel._is_test_mode())


if __name__ == "__main__":
    unittest.main()
