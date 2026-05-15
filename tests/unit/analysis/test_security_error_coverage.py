import unittest
from typing import Any

from src.analysis.checks.exposure import (
    cache_poisoning_indicator_checker,
    dns_misconfiguration_signal_checker,
    password_confirmation_checker,
    rate_limit_header_analyzer,
)
from src.analysis.checks.passive import cookie_security_checker, header_checker
from src.analysis.passive.facade import ssrf_candidate_finder


class FakeResponseCache:
    def __init__(self, records: dict[str, dict[str, Any]]) -> None:
        self.records = dict(records)

    def get(self, url: str) -> dict[str, Any] | None:
        return self.records.get(url)


def make_response(
    url: str,
    *,
    status_code: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
    content_type: str = "text/html",
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


class SecurityErrorCoverageTests(unittest.TestCase):
    def test_no_rate_limiting_on_form_is_flagged(self) -> None:
        findings = rate_limit_header_analyzer([make_response("https://app.example.com/login")])

        self.assertEqual(len(findings), 1)
        self.assertIn("missing_rate_limit_headers", findings[0]["issues"])

    def test_missing_secure_or_httponly_cookie_flags_are_flagged(self) -> None:
        findings = cookie_security_checker(
            [
                make_response(
                    "https://app.example.com/session",
                    headers={"Set-Cookie": "sessionid=abc123; Path=/; SameSite=Lax"},
                )
            ]
        )

        self.assertEqual(len(findings), 1)
        issues = set(findings[0]["issues"])
        self.assertIn("missing_secure:sessionid", issues)
        self.assertIn("missing_httponly:sessionid", issues)

    def test_lack_of_password_confirmation_is_flagged(self) -> None:
        findings = password_confirmation_checker(
            {"https://app.example.com/signup"},
            [
                make_response(
                    "https://app.example.com/signup",
                    body="""<form><input name="password" type="password"></form>""",
                )
            ],
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("missing_password_confirmation_field", findings[0]["issues"])

    def test_mail_server_misconfiguration_signal_is_flagged(self) -> None:
        findings = dns_misconfiguration_signal_checker(
            [
                make_response(
                    "https://app.example.com/dns-debug",
                    body="v=spf1 +all and dkim status shown in debug output",
                    content_type="text/plain",
                )
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("weak_spf_all", findings[0]["indicators"])

    def test_oauth_misconfiguration_signal_is_flagged(self) -> None:
        findings = ssrf_candidate_finder(
            {"https://app.example.com/callback?return_to=http://127.0.0.1/admin"}
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("oauth_redirect_sink", findings[0]["signals"])

    def test_cache_poisoning_indicator_is_flagged(self) -> None:
        findings = cache_poisoning_indicator_checker(
            [
                make_response(
                    "https://app.example.com/cacheable",
                    body="debug x-forwarded-host=poison.attacker.tld",
                    headers={"Cache-Control": "public, max-age=600"},
                )
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertIn("host_header_reflection_in_cacheable_response", findings[0]["issues"])

    def test_lack_of_security_headers_is_flagged(self) -> None:
        response = make_response("https://app.example.com/account", headers={})
        cache = FakeResponseCache({"https://app.example.com/account": response})

        findings = header_checker(["https://app.example.com/account"], cache, {})

        self.assertEqual(len(findings), 1)
        issues = set(findings[0]["issues"])
        self.assertIn("missing_hsts", issues)
        self.assertIn("missing_content_security_policy", issues)
        self.assertIn("missing_x_content_type_options", issues)


if __name__ == "__main__":
    unittest.main()
