import unittest

from src.recon.standardize import standardize_recon_outputs


class ReconLayerStandardizationTests(unittest.TestCase):
    def test_standardize_recon_outputs_emits_candidate_objects(self) -> None:
        candidates = standardize_recon_outputs(
            subdomains={"api.example.com"},
            live_hosts={"https://api.example.com"},
            urls={"https://api.example.com/v1/users?id=1"},
            ranked_urls=[
                {"url": "https://api.example.com/v1/users?id=1", "score": 12, "signals": ["id"]}
            ],
            parameters={"id"},
        )

        kinds = {item.kind for item in candidates}
        self.assertIn("host", kinds)
        self.assertIn("url", kinds)
        self.assertIn("parameter", kinds)
        self.assertTrue(any(item.score == 12 for item in candidates if item.kind == "url"))


if __name__ == "__main__":
    unittest.main()
