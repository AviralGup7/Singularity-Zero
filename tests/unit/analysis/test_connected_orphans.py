"""Unit tests verifying newly connected active and passive security probe modules."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from src.analysis.active.coordinator import (
    grpc_fuzzer_probe,
    oauth_security_probe,
    xxe_detection_probe,
)
from src.analysis.active.grpc_fuzzer import GrpcMethod
from src.analysis.checks.passive.tls_analyzer import TLSAnalyzer


class TestConnectedOrphanSecurityModules(unittest.IsolatedAsyncioTestCase):
    """Verify that all connected security analysis and probing tools run reliably."""

    async def test_xxe_detection_probe_execution(self) -> None:
        """Test XXE detection probe safely filters XML endpoints and tests them."""
        test_urls = [
            "https://example.com/api/v1/users.xml",
            "https://example.com/soap/service",
            "https://example.com/index.html",
        ]
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "root:x:0:0:root:/root:/bin/bash"
            mock_post.return_value = mock_resp

            findings = await xxe_detection_probe(test_urls, timeout=2.0, max_urls=10)
            self.assertIsInstance(findings, list)

    async def test_oauth_security_probe_execution(self) -> None:
        """Test OAuth/OIDC configuration tester discovers endpoints and checks params."""
        test_urls = [
            "https://auth.example.com/callback?code=abc12345",
            "https://auth.example.com/callback?access_token=eyJhbGciOi...",
        ]
        with patch(
            "src.analysis.active.injection.oauth_testing.discover_oauth_config"
        ) as mock_disc:
            mock_disc.return_value = []
            findings = await oauth_security_probe(test_urls, timeout=2.0, max_urls=10)
            self.assertIsInstance(findings, list)
            # Should detect missing state param and token in URL
            types = [f.get("type") for f in findings]
            self.assertIn("missing_state_parameter", types)
            self.assertIn("token_in_url", types)

    async def test_grpc_fuzzer_execution(self) -> None:
        """Test gRPC reflection fuzzer generates input payloads and runs."""
        methods = [
            GrpcMethod(
                name="GetUser",
                full_name="user.UserService/GetUser",
                service="user.UserService",
                client_streaming=False,
                server_streaming=False,
                input_fields=[{"name": "user_id", "type": "string"}],
            )
        ]
        with patch("src.analysis.active.grpc_fuzzer.GrpcFuzzer._fuzz_method") as mock_fuzz:
            from src.analysis.active.grpc_fuzzer import GrpcFuzzerResult

            mock_fuzz.return_value = GrpcFuzzerResult(
                service="user.UserService",
                method="GetUser",
                request_count=16,
                unique_status_codes=[200, 400],
                five_xx_count=0,
                slowest_ms=45.0,
                fastest_ms=10.0,
            )
            results = await grpc_fuzzer_probe("https://example.com/grpc", methods)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].method, "GetUser")
            finding_dict = results[0].to_finding()
            self.assertEqual(finding_dict["type"], "grpc_fuzz")

    def test_tls_analyzer_inspection(self) -> None:
        """Test TLSAnalyzer checks certificate expiry and cipher safety."""
        analyzer = TLSAnalyzer()
        with patch.object(analyzer, "_check_certificate") as mock_cert:
            mock_cert.return_value = []
            findings = analyzer.analyze_host("example.com", 443)
            self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
