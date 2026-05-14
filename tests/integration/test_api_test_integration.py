import unittest

import src.api_tests as api_tests
from src.execution.validators import api_test_integration


class ApiTestIntegrationTests(unittest.TestCase):
    def test_packaged_api_tests_exports_entrypoints(self) -> None:
        self.assertTrue(callable(api_tests.main))
        self.assertTrue(callable(api_tests.build_api_test_result))
        self.assertTrue(callable(api_tests.run_api_key_checklist))

    def test_integration_loads_packaged_api_tests_module(self) -> None:
        api_test_integration._load_api_tester.cache_clear()

        module = api_test_integration._load_api_tester()

        self.assertIsNotNone(module)
        self.assertEqual(module.__name__, api_test_integration.API_TESTER_MODULE)

    def test_build_api_test_result_uses_packaged_result_builder(self) -> None:
        api_test_integration._load_api_tester.cache_clear()

        payload = api_test_integration.build_api_test_result(
            {
                "title": "Potential IDOR",
                "request_context": {
                    "baseline_url": "https://api.example.com/users/123",
                    "mutated_url": "https://api.example.com/users/456",
                    "parameter": "user_id",
                    "variant": "456",
                    "method": "GET",
                },
            }
        )

        self.assertEqual(payload["title"], "Potential IDOR")
        self.assertEqual(payload["baseline_url"], "https://api.example.com/users/123")
        self.assertEqual(payload["variant_url"], "https://api.example.com/users/456")
        self.assertEqual(payload["parameter"], "user_id")
        self.assertEqual(payload["variant"], "456")


if __name__ == "__main__":
    unittest.main()
