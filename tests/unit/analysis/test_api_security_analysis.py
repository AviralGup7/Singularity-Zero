import unittest
from pathlib import Path
from typing import Any
from src.analysis.checks.exposure import (
    graphql_introspection_exposure_checker,
    http_method_exposure_checker,
    openapi_swagger_spec_checker,
)
from src.analysis.json._core.json_analysis._access_control import (
    privilege_escalation_detector,
)
from src.analysis.json._core.json_analysis._role_diff import (
    role_based_endpoint_comparison,
)
from src.analysis.json.auth import (
    multi_endpoint_auth_consistency_check,
    unauth_access_check,
)
from src.analysis.response._core.response_analysis._redirect_analysis import (
    auth_boundary_redirect_detection,
)
from src.dashboard.services import DashboardHandler, DashboardServices
from src.execution.validators.validators.idor import (
    promote_evidence_backed_results,
    validate_idor_candidates,
)



pass  # DashboardHandler removed - legacy server eliminated


def make_response(
    url: str,
    *,
    status_code: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
    content_type: str = "application/json",
    final_url: str | None = None,
) -> dict[str, Any]:
    normalized_headers = dict(headers or {})
    resolved_final_url = final_url or url
    redirect_chain = [url]
    if resolved_final_url != url:
        redirect_chain.append(resolved_final_url)
    return {
        "requested_url": url,
        "request_method": "GET",
        "url": resolved_final_url,
        "final_url": resolved_final_url,
        "status_code": status_code,
        "headers": normalized_headers,
        "content_type": content_type,
        "body_text": body,
        "body_length": len(body),
        "truncated": False,
        "redirect_chain": redirect_chain,
        "redirect_count": max(len(redirect_chain) - 1, 0),
    }


class FakeResponseCache:
    def __init__(
        self,
        base_records: dict[str, dict[str, Any]],
        requested_records: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.base_records = dict(base_records)
        self.requested_records = dict(requested_records or {})
        self.requests: list[tuple[str, str, dict[str, str]]] = []

    def get(self, url: str) -> dict[str, Any] | None:
        return self.base_records.get(url)

    def request(
        self, url: str, *, method: str = "GET", headers: dict[str, str] | None = None
    ) -> dict[str, Any] | None:
        self.requests.append((url, method, dict(headers or {})))
        return self.requested_records.get(url, self.base_records.get(url))


class PassiveApiExposureTests(unittest.TestCase):
    def test_graphql_introspection_exposure_checker_flags_schema_responses(self) -> None:
        findings = graphql_introspection_exposure_checker(
            [
                make_response(
                    "https://api.example.com/graphql",
                    body='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                )
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["indicator"], "graphql_introspection_enabled")
        self.assertEqual(findings[0]["endpoint_type"], "API")

    def test_openapi_swagger_spec_checker_flags_path_and_schema_exposure(self) -> None:
        findings = openapi_swagger_spec_checker(
            {"https://api.example.com/swagger.json"},
            [make_response("https://api.example.com/openapi.json", body='{"openapi":"3.0.3"}')],
        )

        indicators = {item["indicator"] for item in findings}
        self.assertEqual(indicators, {"openapi_path_hint", "openapi_schema_exposed"})

    def test_http_method_exposure_checker_flags_risky_methods(self) -> None:
        findings = http_method_exposure_checker(
            [
                make_response(
                    "https://api.example.com/api/users",
                    headers={"Allow": "GET, POST, DELETE, TRACE"},
                    body='{"ok":true}',
                )
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risky_methods"], ["DELETE", "TRACE"])


class BrokenAccessControlAnalysisTests(unittest.TestCase):
    def test_role_based_endpoint_comparison_detects_role_context_changes(self) -> None:
        findings = role_based_endpoint_comparison(
            [
                make_response(
                    "https://api.example.com/api/reports?role=user",
                    body='{"records":[]}',
                ),
                make_response(
                    "https://api.example.com/api/reports?role=admin",
                    body='{"records":[{"id":"1","secret":"internal"}],"admin":true}',
                ),
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["role_contexts"], ["role"])
        self.assertIn("role_context_switch", findings[0]["signals"])

    def test_multi_endpoint_auth_consistency_check_flags_mixed_enforcement(self) -> None:
        responses = [
            make_response(
                "https://api.example.com/api/profile",
                body='{"id":"1","email":"user@example.com","account_id":"acct_1"}',
            ),
            make_response(
                "https://api.example.com/api/admin",
                status_code=403,
                body='{"error":"forbidden"}',
            ),
        ]

        findings = multi_endpoint_auth_consistency_check(responses)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["signals"], ["mixed_auth_enforcement"])
        self.assertEqual(findings[0]["accessible_auth_count"], 1)
        self.assertEqual(findings[0]["restricted_count"], 1)

    def test_privilege_escalation_detector_flags_access_gained_after_role_mutation(self) -> None:
        url = "https://api.example.com/api/projects?role=user"
        mutated_url = "https://api.example.com/api/projects?role=admin"
        cache = FakeResponseCache(
            {
                url: make_response(url, status_code=403, body='{"error":"forbidden"}'),
            },
            {
                mutated_url: make_response(
                    mutated_url,
                    body='{"id":"1","tenant_id":"tenant-1","name":"Secret Project"}',
                )
            },
        )

        findings = privilege_escalation_detector([url], cache)

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["accessible_after_role_change"])
        self.assertIn("access_gained", findings[0]["signals"])
        self.assertEqual(cache.requests[0][0], mutated_url)

    def test_unauth_access_check_flags_authenticated_json_visible_without_auth(self) -> None:
        url = "https://api.example.com/api/profile"
        baseline = make_response(
            url, body='{"id":"1","email":"user@example.com","account_id":"acct_1"}'
        )
        cache = FakeResponseCache({url: baseline}, {url: baseline})

        findings = unauth_access_check([url], cache)

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["same_status"])
        self.assertEqual(findings[0]["evidence_level"], "strong")
        self.assertTrue(findings[0]["json_accessible"])
        self.assertEqual(cache.requests[0][2]["Authorization"], "")

    def test_unauth_access_check_skips_tokenized_urls(self) -> None:
        url = "https://api.example.com/api/profile?access_token=secret"
        cache = FakeResponseCache({url: make_response(url, body='{"id":"1"}')})

        findings = unauth_access_check([url], cache)

        self.assertEqual(findings, [])
        self.assertEqual(cache.requests, [])

    def test_auth_boundary_redirect_detection_flags_cross_host_redirects(self) -> None:
        url = "https://auth.example.com/login?return_to=%2Fdashboard"
        cache = FakeResponseCache(
            {
                url: make_response(
                    url,
                    status_code=302,
                    headers={"Location": "https://app.example.com/dashboard"},
                    final_url="https://app.example.com/dashboard",
                    content_type="text/html",
                )
            }
        )

        findings = auth_boundary_redirect_detection([url], cache)  # type: ignore[arg-type]  # type: ignore[arg-type]

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["boundary_changed"])
        self.assertIn("cross_host", findings[0]["signals"])
        self.assertIn("pre_login", findings[0]["signals"])

    def test_validate_idor_candidates_promotes_comparison_backed_results(self) -> None:
        analysis_results = {
            "idor_candidate_finder": [
                {
                    "url": "https://api.example.com/api/users?user_id=1",
                    "score": 8,
                    "signals": ["numeric_identifier", "response_similarity"],
                    "query_keys": ["user_id"],
                    "comparison": {
                        "body_similarity": 0.94,
                        "mutated_url": "https://api.example.com/api/users?user_id=2",
                        "shared_key_fields": ["email", "name"],
                    },
                    "has_numeric_identifier": True,
                }
            ]
        }

        findings = validate_idor_candidates(
            analysis_results, {"replayable_locations": ["response_body"]}
        )
        promoted = promote_evidence_backed_results(findings)

        self.assertEqual(findings[0]["validation_state"], "response_similarity_match")
        self.assertIn("user_id=1", findings[0]["identifier_hints"])
        self.assertEqual(promoted[0]["severity"], "high")
        self.assertEqual(
            promoted[0]["evidence"]["mutated_url"], "https://api.example.com/api/users?user_id=2"
        )


class DashboardJsonApiNormalizationTests(unittest.TestCase):
    def test_json_boolean_false_values_disable_analysis_flags(self) -> None:
        workspace_root = Path(__file__).resolve().parents[2]
        handler = DashboardHandler.__new__(DashboardHandler)
        handler.services = DashboardServices(
            workspace_root, workspace_root, workspace_root / "configs/config.example.json"
        )

        params = handler._json_to_params(
            {
                "analysis_enabled": False,
                "idor_candidate_finder_present": True,
                "idor_candidate_finder": False,
                "refresh_cache": False,
            }
        )
        form_values = handler._extract_form_values(params)
        execution_options = handler._extract_execution_options(params)

        self.assertEqual(params["analysis_enabled"], ["0"])
        self.assertEqual(form_values["analysis_enabled"], "0")
        self.assertEqual(form_values["idor_candidate_finder"], "0")
        self.assertFalse(execution_options["refresh_cache"])


if __name__ == "__main__":
    unittest.main()
