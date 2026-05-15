import unittest
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from src.analysis.intelligence.endpoint.endpoint_intelligence import build_endpoint_intelligence
from src.analysis.intelligence.findings.intelligence_findings import (
    merge_findings,
)
from src.analysis.response.mutations import (
    auth_header_tampering_variations,
    json_mutation_attacks,
    multi_step_flow_breaking_probe,
    parameter_pollution_exploitation,
)
from src.recon.common import normalize_url


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
        request_headers = dict(headers or {})
        self.requests.append((url, method, request_headers))
        if url in self.requested_records:
            return self.requested_records[url]
        if (
            request_headers.get("Authorization", "__missing__") == ""
            and request_headers.get("Cookie", "__missing__") == ""
        ):
            return self.base_records.get(url)
        if request_headers.get("Authorization", "__missing__").startswith("Bearer invalid"):
            return make_response(url, status_code=401, body='{"error":"invalid_token"}')
        if request_headers.get("Authorization") == "Basic ZHVtbXk6dGVzdA==":
            return make_response(url, status_code=401, body='{"error":"basic_not_allowed"}')
        return self.base_records.get(url)


class ControlledAttackProbeTests(unittest.TestCase):
    def test_parameter_pollution_exploitation_detects_duplicate_parameter_effect(self) -> None:
        url = "https://api.example.com/api/orders?include=summary"
        parsed = urlparse(url)
        polluted_url = normalize_url(
            urlunparse(
                parsed._replace(
                    query=urlencode([("include", "summary"), ("include", "all")], doseq=True)
                )
            )
        )
        cache = FakeResponseCache(
            {url: make_response(url, body='{"records":[{"id":"1"}]}')},
            {
                polluted_url: make_response(
                    polluted_url, body='{"records":[{"id":"1"}],"admin_view":true}'
                )
            },
        )

        findings = parameter_pollution_exploitation([url], cache)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "include")
        self.assertEqual(findings[0]["strategy"], "duplicate_parameter_append")
        self.assertIn("duplicate_parameter_append", findings[0]["signals"])

    def test_auth_header_tampering_variations_detect_possible_auth_bypass(self) -> None:
        url = "https://api.example.com/api/profile"
        cache = FakeResponseCache(
            {url: make_response(url, body='{"id":"1","email":"user@example.com"}')}
        )

        findings = auth_header_tampering_variations([url], cache)

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["auth_bypass_variant"])
        self.assertIn("possible_auth_bypass", findings[0]["signals"])
        variations = {item["variation"] for item in findings[0]["observations"]}
        self.assertIn("stripped_auth", variations)
        self.assertIn("invalid_bearer", variations)

    def test_json_mutation_attacks_detect_json_shaped_query_mutations(self) -> None:
        url = "https://api.example.com/api/search?filter=active"
        parsed = urlparse(url)
        object_url = normalize_url(
            urlunparse(parsed._replace(query=urlencode([("filter", '{"probe":true}')], doseq=True)))
        )
        array_url = normalize_url(
            urlunparse(
                parsed._replace(query=urlencode([("filter", '["probe","alt"]')], doseq=True))
            )
        )
        cache = FakeResponseCache(
            {url: make_response(url, body='{"results":[{"id":"1"}]}')},
            {
                object_url: make_response(object_url, body='{"error":"object_filter_not_allowed"}'),
                array_url: make_response(array_url, body='{"results":[{"id":"1"},{"id":"2"}]}'),
            },
        )

        findings = json_mutation_attacks([url], cache)  # type: ignore[arg-type]  # type: ignore[arg-type]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "filter")
        self.assertIn("json_mutation_probe", findings[0]["signals"])
        self.assertGreaterEqual(len(findings[0]["observations"]), 1)

    def test_multi_step_flow_breaking_probe_flags_direct_access_to_later_step(self) -> None:
        entry_url = "https://app.example.com/cart"
        candidate = "https://app.example.com/checkout/confirm"
        cache = FakeResponseCache(
            {
                entry_url: make_response(
                    entry_url, content_type="text/html", body="<html>cart</html>"
                )
            },
            {
                candidate: make_response(
                    candidate, content_type="text/html", body="<html>confirm</html>"
                )
            },
        )

        findings = multi_step_flow_breaking_probe(
            [{"label": "checkout_flow", "chain": [entry_url, candidate]}], cache
        )  # type: ignore[arg-type]  # type: ignore[arg-type]

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["step_skip_possible"])
        self.assertEqual(findings[0]["skipped_to_url"], candidate)
        self.assertIn("flow_break_candidate", findings[0]["signals"])

    def test_new_controlled_probes_feed_findings_and_endpoint_intelligence(self) -> None:
        url = "https://api.example.com/api/profile?view=summary"
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "parameter_pollution_exploitation": [
                {
                    "url": url,
                    "endpoint_key": "|/api/profile|",
                    "endpoint_base_key": "|/api/profile|",
                    "status_changed": False,
                    "content_changed": True,
                    "signals": ["duplicate_parameter_append", "content_divergence"],
                }
            ],
            "auth_header_tampering_variations": [
                {
                    "url": url,
                    "endpoint_key": "|/api/profile|",
                    "endpoint_base_key": "|/api/profile|",
                    "auth_bypass_variant": True,
                    "signals": ["auth_header_variation", "possible_auth_bypass"],
                    "observations": [{"variation": "stripped_auth", "auth_bypass_variant": True}],
                }
            ],
            "json_mutation_attacks": [
                {
                    "url": url,
                    "endpoint_key": "|/api/profile|",
                    "endpoint_base_key": "|/api/profile|",
                    "observations": [{"variant": "json_object", "status_changed": True}],
                    "signals": ["json_mutation_probe", "status_divergence"],
                }
            ],
            "parameter_pollution_status_change": [
                {
                    "url": url,
                    "endpoint_key": "|/api/profile|",
                    "endpoint_base_key": "|/api/profile|",
                    "status_changed": True,
                    "signals": ["duplicate_parameter_append", "status_divergence"],
                }
            ],
            "multi_step_flow_breaking_probe": [
                {
                    "url": url,
                    "endpoint_key": "|/api/profile|",
                    "endpoint_base_key": "|/api/profile|",
                    "step_skip_possible": True,
                    "signals": ["direct_step_access", "flow_break_candidate"],
                }
            ],
        }

        findings = merge_findings(
            analysis_results, [{"url": url, "score": 18}], {"api_heavy": True}, "safe"
        )
        titles = {item["title"] for item in findings}
        self.assertIn("Duplicate parameter replay changes endpoint behavior", titles)
        self.assertIn("Auth header variation changes enforcement behavior", titles)
        self.assertIn("JSON-shaped parameter mutation changes API behavior", titles)
        self.assertIn("Later workflow step appears directly reachable", titles)

        intelligence = build_endpoint_intelligence([{"url": url, "score": 18}], analysis_results)
        self.assertEqual(len(intelligence), 1)
        self.assertIn("parameter_pollution_exploitation", intelligence[0]["evidence_modules"])
        self.assertIn("auth_header_tampering_variations", intelligence[0]["evidence_modules"])
        self.assertIn("json_mutation_attacks", intelligence[0]["evidence_modules"])
        self.assertIn("multi_step_flow_breaking_probe", intelligence[0]["evidence_modules"])


if __name__ == "__main__":
    unittest.main()
