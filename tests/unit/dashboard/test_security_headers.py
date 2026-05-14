import unittest

from src.dashboard.fastapi.validation import security_headers


class SecurityHeadersTests(unittest.TestCase):
    def test_returns_expected_headers(self) -> None:
        headers = security_headers()
        self.assertIn("Strict-Transport-Security", headers)
        self.assertIn("X-Content-Type-Options", headers)
        self.assertIn("X-Frame-Options", headers)
        self.assertIn("Content-Security-Policy", headers)
        self.assertIn("Referrer-Policy", headers)
        self.assertIn("Permissions-Policy", headers)

    def test_hsts_value(self) -> None:
        headers = security_headers()
        self.assertEqual(
            headers["Strict-Transport-Security"],
            "max-age=31536000; includeSubDomains",
        )

    def test_x_content_type_options_value(self) -> None:
        headers = security_headers()
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_x_frame_options_value(self) -> None:
        headers = security_headers()
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_content_security_policy_value(self) -> None:
        headers = security_headers()
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("style-src 'self' https://fonts.googleapis.com 'unsafe-inline'", csp)
        self.assertIn("font-src 'self' https://fonts.gstatic.com", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_referrer_policy_value(self) -> None:
        headers = security_headers()
        self.assertEqual(headers["Referrer-Policy"], "strict-origin-when-cross-origin")

    def test_permissions_policy_value(self) -> None:
        headers = security_headers()
        self.assertEqual(
            headers["Permissions-Policy"],
            "geolocation=(), camera=(), microphone=()",
        )


if __name__ == "__main__":
    unittest.main()
