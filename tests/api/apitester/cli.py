import json

from .baseline_variant import test_api_baseline_vs_variant


def main() -> int:
    test_item = {
        "title": "Potential IDOR",
        "request_context": {
            "baseline_url": "https://api.example.com/users/123",
            "mutated_url": "https://api.example.com/users/456",
            "parameter": "user_id",
            "variant": "456",
            "method": "GET",
        },
    }
    print(json.dumps(test_api_baseline_vs_variant(test_item), indent=2))
    return 0
