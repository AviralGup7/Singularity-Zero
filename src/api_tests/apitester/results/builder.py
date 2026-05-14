from typing import Any

from ..result_view import build_result_view


def build_api_test_result(item: dict[str, Any]) -> dict[str, str]:
    result_view = build_result_view(item)
    summary_lines = [
        f"Observed Baseline URL: {result_view['baseline_url']}",
        f"Observed Variant URL: {result_view['variant_url']}",
        f"Observed Method: {result_view['request_method']}",
        f"Observed Mutation: {result_view['parameter']}={result_view['variant']}"
        if result_view["parameter"] != "n/a" or result_view["variant"] != "n/a"
        else "Observed Mutation: n/a",
        f"Status Changed: {result_view['status_changed']}",
        f"Redirect Changed: {result_view['redirect_changed']}",
        f"Content Changed: {result_view['content_changed']}",
        f"Trust Boundary Shift: {result_view['trust_boundary_shift']}",
        f"Body Similarity: {result_view['body_similarity']}",
        f"Length Delta: {result_view['length_delta']}",
        f"Shared Key Fields: {result_view['shared_key_fields']}",
        f"Replay ID: {result_view['replay_id']}",
    ]

    return {
        "title": str(result_view["title"]),
        "summary": "\n".join(summary_lines),
        "baseline_url": str(result_view["baseline_url"]),
        "variant_url": str(result_view["variant_url"]),
        "parameter": str(result_view["parameter"]),
        "variant": str(result_view["variant"]),
    }
