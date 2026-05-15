import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from src.pipeline.services.pipeline_flow import pipeline_flow_manifest
from src.pipeline.storage import load_config
from src.reporting import build_summary
from src.reporting.pages import generate_run_report
from src.reporting.vrt_coverage import build_p1_vrt_coverage


class ReportingVrtIntegrationTests(unittest.TestCase):
    def _build_summary_fixture(self) -> dict[str, Any]:
        config = load_config(
            Path(__file__).resolve().parents[2] / "configs" / "config.example.json"
        )
        vrt_coverage = build_p1_vrt_coverage(config)
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "ai_endpoint_exposure_analyzer": [
                {
                    "url": "https://api.example.com/v1/chat/completions",
                    "signals": ["model_family_hint", "provider_key_exposed"],
                }
            ],
            "cross_tenant_pii_risk_analyzer": [
                {
                    "url": "https://api.example.com/api/users",
                    "identity_fields": ["tenant_id", "user_id"],
                    "pii_fields": ["email"],
                }
            ],
            "server_side_injection_surface_analyzer": [
                {
                    "url": "https://api.example.com/report?query=users",
                    "vulnerability_types": ["sql_injection"],
                    "signals": ["param:query", "response_error_hint"],
                }
            ],
            "parameter_pollution_exploitation": [
                {
                    "url": "https://api.example.com/api/users?view=summary",
                    "parameter": "view",
                    "signals": ["duplicate_parameter_append", "content_divergence"],
                }
            ],
            "auth_header_tampering_variations": [
                {
                    "url": "https://api.example.com/api/users",
                    "auth_bypass_variant": True,
                    "signals": ["auth_header_variation", "possible_auth_bypass"],
                }
            ],
            "json_mutation_attacks": [
                {
                    "url": "https://api.example.com/api/users?filter=active",
                    "parameter": "filter",
                    "signals": ["json_mutation_probe", "status_divergence"],
                }
            ],
            "multi_step_flow_breaking_probe": [
                {
                    "url": "https://api.example.com/checkout/start",
                    "step_skip_possible": True,
                    "signals": ["direct_step_access", "flow_break_candidate"],
                }
            ],
        }
        merged_findings = [
            {
                "title": "AI inference or model surface detected",
                "url": "https://api.example.com/v1/chat/completions",
                "severity": "medium",
                "confidence": 0.7,
                "score": 60,
                "category": "ai_surface",
                "endpoint_type": "API",
                "history_status": "new",
                "next_step": "Review the AI-oriented endpoint for model enumeration, prompt leakage, throttling, and exposed provider keys.",
                "evidence": {
                    "endpoint_key": "|/v1/chat/completions|",
                    "signals": ["model_family_hint"],
                },
            },
            {
                "title": "Cross-tenant PII exposure indicator",
                "url": "https://api.example.com/api/users",
                "severity": "high",
                "confidence": 0.83,
                "score": 90,
                "category": "access_control",
                "endpoint_type": "API",
                "history_status": "new",
                "next_step": "Compare the tenant, account, and user identifiers in the response and verify whether returned records cross an expected tenant boundary.",
                "evidence": {"endpoint_key": "|/api/users|", "signals": ["tenant_id", "email"]},
            },
        ]
        return build_summary(
            target_name="demo-target",
            scope_entries=["example.com"],
            subdomains={"api.example.com"},
            live_records=[{"url": "https://api.example.com"}],
            urls={
                "https://api.example.com/v1/chat/completions",
                "https://api.example.com/api/users",
            },
            parameters={"query", "tenant_id"},
            priority_urls={"https://api.example.com/api/users"},
            ranked_priority_urls=[{"url": "https://api.example.com/api/users", "score": 17}],
            screenshots=[],
            analysis_results=analysis_results,
            merged_findings=merged_findings,
            tools={"httpx": True},
            module_metrics={"analysis": {"status": "ok", "duration_seconds": 1.2}},
            attack_surface={"ai_surface": 1, "access_control": 1},
            target_profile={"api_heavy": True},
            technology_summary=[{"technology": "React", "count": 2}],
            endpoint_intelligence=[
                {
                    "url": "https://api.example.com/api/users",
                    "score": 17,
                    "signals": ["idor"],
                    "flow_labels": ["api"],
                    "decision": "HIGH",
                }
            ],
            trend_summary={"new_findings": 2, "resolved_findings": 0, "stable_findings": 0},
            next_steps=["Review the AI-oriented endpoints and cross-tenant response shapes."],
            high_confidence_shortlist=[
                {
                    "title": "Cross-tenant PII exposure indicator",
                    "url": "https://api.example.com/api/users",
                    "category": "access_control",
                    "severity": "high",
                    "confidence": 0.83,
                    "history_status": "new",
                    "combined_signal": "",
                    "next_step": "Verify tenant boundaries.",
                }
            ],
            manual_verification_queue=[],
            cross_finding_correlation=[],
            vrt_coverage=vrt_coverage,
            verified_exploits=[],
            validation_summary={"results": {}, "callback_context": {}, "token_replay": {}},
            review_settings={"top_findings_limit": 5, "verified_exploit_limit": 3},
            validation_settings={},
            started_at=time.time() - 1,
            previous_run=None,
            pipeline_flow=pipeline_flow_manifest(),
        )

    def test_build_summary_surfaces_vrt_counts_in_run_counts(self) -> None:
        summary = self._build_summary_fixture()

        self.assertEqual(summary["counts"]["vrt_direct"], 10)
        self.assertEqual(summary["counts"]["vrt_signal_only"], 11)
        self.assertEqual(summary["counts"]["vrt_unsupported"], 9)
        self.assertEqual(summary["counts"]["ai_endpoint_exposure_analyzer"], 1)
        self.assertEqual(summary["counts"]["cross_tenant_pii_risk_analyzer"], 1)
        self.assertEqual(summary["counts"]["server_side_injection_surface_analyzer"], 1)
        self.assertEqual(summary["counts"]["parameter_pollution_exploitation"], 1)
        self.assertEqual(summary["counts"]["auth_header_tampering_variations"], 1)
        self.assertEqual(summary["counts"]["json_mutation_attacks"], 1)
        self.assertEqual(summary["counts"]["multi_step_flow_breaking_probe"], 1)
        self.assertIn("generated_at_ist", summary)
        self.assertIn("+05:30", summary["generated_at_ist"])

    def test_generate_run_report_renders_vrt_and_new_analyzer_sections(self) -> None:
        summary = self._build_summary_fixture()
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "ai_endpoint_exposure_analyzer": [
                {
                    "url": "https://api.example.com/v1/chat/completions",
                    "signals": ["model_family_hint"],
                }
            ],
            "cross_tenant_pii_risk_analyzer": [
                {"url": "https://api.example.com/api/users", "identity_fields": ["tenant_id"]}
            ],
            "server_side_injection_surface_analyzer": [
                {
                    "url": "https://api.example.com/report?query=users",
                    "vulnerability_types": ["sql_injection"],
                }
            ],
            "parameter_pollution_exploitation": [
                {"url": "https://api.example.com/api/users?view=summary", "parameter": "view"}
            ],
            "auth_header_tampering_variations": [
                {"url": "https://api.example.com/api/users", "auth_bypass_variant": True}
            ],
            "json_mutation_attacks": [
                {"url": "https://api.example.com/api/users?filter=active", "parameter": "filter"}
            ],
            "multi_step_flow_breaking_probe": [
                {"url": "https://api.example.com/checkout/start", "step_skip_possible": True}
            ],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            run_dir = Path(temp_dir)
            generate_run_report(
                run_dir=run_dir,
                summary=summary,
                diff_summary=None,
                screenshots=[],
                priority_urls={"https://api.example.com/api/users"},
                parameters={"query"},
                analysis_results=analysis_results,
            )

            report = (run_dir / "report.html").read_text(encoding="utf-8")

        self.assertIn("P1 VRT Coverage", report)
        self.assertIn("requested total", report.lower())
        self.assertIn("AI Endpoint Exposure Analyzer", report)
        self.assertIn("Cross-Tenant PII Risk Analyzer", report)
        self.assertIn("Server-Side Injection Surface Analyzer", report)
        self.assertIn("Parameter Pollution Exploitation", report)
        self.assertIn("Auth Header Tampering Variations", report)
        self.assertIn("JSON Mutation Attacks", report)
        self.assertIn("Multi-Step Flow Breaking Probe", report)
        self.assertIn("Endpoint Relationship Graph", report)
        self.assertIn("Finding Graph", report)
        self.assertIn("Shared Parameter Tracking", report)
        self.assertIn("Auth Context Mapping", report)
        self.assertIn("demo-target", report)
        self.assertIn("IST (+05:30)", report)


if __name__ == "__main__":
    unittest.main()
