import unittest
from typing import Any

from src.analysis.behavior.service_findings import (
    default_credential_hints,
    dev_staging_environment_detection,
    port_scan_integration,
    tls_ssl_misconfiguration_checks,
)
from src.analysis.checks.active import stored_xss_signal_detector
from src.analysis.checks.exposure import (
    environment_file_exposure_checker,
    public_repo_exposure_checker,
    rate_limit_header_analyzer,
    subdomain_takeover_indicator_checker,
)
from src.analysis.checks.passive import sensitive_data_scanner
from src.analysis.passive.facade import ssrf_candidate_finder, token_leak_detector


def make_response(
    url: str,
    *,
    status_code: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
    content_type: str = "application/json",
) -> dict[str, Any]:
    return {
        "requested_url": url,
        "request_method": "GET",
        "url": url,
        "final_url": url,
        "status_code": status_code,
        "headers": dict(headers or {}),
        "content_type": content_type,
        "body_text": body,
        "body_length": len(body),
        "truncated": False,
        "redirect_chain": [url],
        "redirect_count": 0,
    }


class AdditionalSecurityDetectorTests(unittest.TestCase):
    def test_sensitive_data_scanner_detects_private_key_and_ai_api_key(self) -> None:
        findings = sensitive_data_scanner(
            [
                make_response(
                    "https://app.example.com/debug",
                    body="-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\nconst key='sk-proj-abcdefghijklmnopqrstuvwxyz123456';",
                    content_type="text/plain",
                )
            ]
        )

        indicators = {item["indicator"] for item in findings}
        self.assertIn("private_key_block", indicators)
        self.assertIn("openai_api_key", indicators)

    def test_token_leak_detector_flags_query_parameter_and_response_body(self) -> None:
        findings = token_leak_detector(
            {"https://api.example.com/api/profile?access_token=secret-token-value"},
            [
                make_response(
                    "https://api.example.com/api/session",
                    body='{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature","bearer":"Bearer abcd1234efgh5678"}',
                )
            ],
        )

        locations = {item["location"] for item in findings}
        self.assertIn("query_parameter", locations)
        self.assertIn("response_body", locations)

    def test_token_leak_detector_flags_referer_risk_for_external_reference(self) -> None:
        findings = token_leak_detector(
            {"https://api.example.com/api/profile?access_token=secret-token-value"},
            [
                make_response(
                    "https://api.example.com/api/profile?access_token=secret-token-value",
                    body='<img src="https://cdn.attacker.net/pixel.png">',
                    content_type="text/html",
                )
            ],
        )

        referer_risk = next(item for item in findings if item["location"] == "referer_risk")
        self.assertIn("cdn.attacker.net", referer_risk["external_hosts"])

    def test_ssrf_candidate_finder_flags_internal_host_and_oauth_adjacent_sink(self) -> None:
        findings = ssrf_candidate_finder(
            {
                "https://app.example.com/callback?return_to=http://127.0.0.1:8080/admin",
                "https://app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
            }
        )

        self.assertEqual(len(findings), 2)
        oauth_item = next(item for item in findings if "return_to=" in item["url"])
        fetch_item = next(item for item in findings if "/fetch" in item["url"])
        self.assertIn("oauth_redirect_sink", oauth_item["signals"])
        self.assertTrue(
            any(signal.startswith("internal_host_reference") for signal in fetch_item["signals"])
        )

    def test_rate_limit_header_analyzer_flags_missing_headers_on_api_endpoint(self) -> None:
        findings = rate_limit_header_analyzer(
            [
                make_response(
                    "https://api.example.com/api/orders",
                    body='{"orders":[]}',
                )
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("missing_rate_limit_headers", findings[0]["issues"])

    def test_stored_xss_signal_detector_flags_dangerous_markup(self) -> None:
        findings = stored_xss_signal_detector(
            [
                make_response(
                    "https://app.example.com/api/comments",
                    body='{"comments":[{"message":"<img src=x onerror=alert(1)>"}]}',
                )
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["indicator"], "stored_xss_candidate")
        self.assertIn("event_handler", findings[0]["xss_signals"])

    def test_public_repo_and_environment_exposure_checkers_flag_sensitive_artifacts(self) -> None:
        repo_findings = public_repo_exposure_checker(
            {"https://app.example.com/.git/config"},
            [
                make_response(
                    "https://app.example.com/.git/config",
                    body="[core]\n\trepositoryformatversion = 0",
                    content_type="text/plain",
                )
            ],
        )
        env_findings = environment_file_exposure_checker(
            {"https://app.example.com/.env"},
            [
                make_response(
                    "https://app.example.com/.env",
                    body="APP_ENV=prod\nDB_PASSWORD=secret",
                    content_type="text/plain",
                )
            ],
        )

        self.assertEqual({item["indicator"] for item in repo_findings}, {"repo_metadata_path"})
        self.assertEqual(
            {item["indicator"] for item in env_findings},
            {"env_or_config_path", "env_file_contents"},
        )

    def test_subdomain_takeover_indicator_checker_flags_dangling_service_text(self) -> None:
        findings = subdomain_takeover_indicator_checker(
            {"https://stale.example.com"},
            [
                make_response(
                    "https://stale.example.com",
                    body="There isn't a GitHub Pages site here.",
                    content_type="text/html",
                )
            ],
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["indicator"], "dangling_service_indicator")

    def test_default_credential_hints_flags_known_admin_service(self) -> None:
        findings = default_credential_hints(
            [
                {
                    "url": "https://ops.example.com:8443",
                    "scheme": "https",
                    "host": "ops.example.com",
                    "port": 8443,
                    "title": "Grafana Login",
                    "body_excerpt": "grafana admin console",
                    "headers": {"server": "nginx"},
                }
            ],
            [],
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("grafana", findings[0]["services"])

    def test_tls_and_dev_staging_detectors_flag_environment_and_certificate_issues(self) -> None:
        live_records = [
            {
                "url": "https://staging.example.com",
                "scheme": "https",
                "host": "staging.example.com",
                "port": 443,
                "title": "staging dashboard",
                "body_excerpt": "welcome to qa",
                "tls": {
                    "not_after": "2020-01-01T00:00:00Z",
                    "self_signed": True,
                    "version": "TLSv1.0",
                },
            }
        ]

        tls_findings = tls_ssl_misconfiguration_checks(live_records)
        env_findings = dev_staging_environment_detection(live_records)

        self.assertEqual(len(tls_findings), 1)
        self.assertEqual(
            set(tls_findings[0]["issues"]),
            {"certificate_expired", "self_signed_certificate", "weak_tls_version"},
        )
        self.assertEqual(len(env_findings), 1)
        self.assertIn("staging", env_findings[0]["signals"])

    def test_port_scan_integration_omits_empty_url_for_tcp_services(self) -> None:
        findings = port_scan_integration(
            [
                {
                    "host": "db.example.com",
                    "port": 5432,
                    "scheme": "",
                    "service_type": "tcp",
                }
            ],
            original_live_hosts=set(),
            records_by_url={},
        )

        self.assertEqual(len(findings), 1)
        self.assertNotIn("url", findings[0])


if __name__ == "__main__":
    unittest.main()
