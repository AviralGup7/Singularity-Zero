"""API tester integration for running API key checklist validations.

Loads the packaged API tester module and delegates checklist execution.
"""

import importlib
from functools import lru_cache
from typing import Any

from src.core.contracts.pipeline import TIMEOUT_DEFAULTS

API_TESTER_MODULE = "src.api_tests.apitester"


@lru_cache(maxsize=1)
def _load_api_tester() -> Any:
    """Load the packaged API tester module.

    Returns:
        Imported module or None if not available.
    """
    try:
        return importlib.import_module(API_TESTER_MODULE)
    except ImportError, ModuleNotFoundError:
        return None


def run_api_key_checklist(
    urls: list[str] | set[str],
    responses: list[dict[str, Any]],
    timeout: int = int(TIMEOUT_DEFAULTS["api_test_seconds"]),
    candidate_limit: int = 6,
) -> dict[str, Any]:
    module = _load_api_tester()
    if module and hasattr(module, "run_api_key_checklist"):
        payload = module.run_api_key_checklist(
            urls, responses, timeout=timeout, candidate_limit=candidate_limit
        )
        if isinstance(payload, dict):
            return payload
    return {
        "status": "unavailable",
        "candidates_tested": 0,
        "results": [],
    }


def build_api_test_result(item: dict[str, Any]) -> dict[str, str]:
    module = _load_api_tester()
    if module and hasattr(module, "build_api_test_result"):
        payload = module.build_api_test_result(item)
        if isinstance(payload, dict):
            return {
                "title": str(payload.get("title", "")).strip(),
                "summary": str(payload.get("summary", "")).strip(),
                "baseline_url": str(payload.get("baseline_url", "")).strip(),
                "variant_url": str(payload.get("variant_url", "")).strip(),
                "parameter": str(payload.get("parameter", "")).strip(),
                "variant": str(payload.get("variant", "")).strip(),
            }
    return {
        "title": str(item.get("title") or "API test").strip(),
        "summary": "No observed API test result is available for this item.",
        "baseline_url": "",
        "variant_url": "",
        "parameter": "",
        "variant": "",
    }
