"""Response delta classification rules.

Contains the core classification logic for determining the significance
of response changes between baseline and mutated requests.
Extracted from response_filter.py for better separation of concerns.
"""


def classify_response_delta(
    *,
    original_status: int | None,
    mutated_status: int | None,
    body_similarity: float,
    length_delta: int,
    redirect_changed: bool,
) -> dict[str, object]:
    """Classify the significance of a response change between two requests."""
    status_from = int(original_status or 0)
    status_to = int(mutated_status or 0)
    similarity = round(float(body_similarity), 3)
    delta = int(length_delta)

    if status_from == status_to and similarity >= 0.985 and delta <= 40 and not redirect_changed:
        return {
            "classification": "ignore",
            "score": 0,
            "reason": "Same status with near-identical body.",
            "include": False,
        }

    if status_from == 200 and status_to == 403:
        return {
            "classification": "auth_enforcement_change",
            "score": 9,
            "reason": "Status moved from 200 to 403.",
            "include": True,
        }

    if status_from == 200 and status_to == 302:
        return {
            "classification": "redirect_gate_change",
            "score": 8,
            "reason": "Status moved from 200 to 302.",
            "include": True,
        }

    if status_from in {401, 403} and status_to == 200:
        return {
            "classification": "auth_bypass_indicator",
            "score": 10,
            "reason": "Status moved from auth-denied to 200.",
            "include": True,
        }

    if status_to == 500:
        if status_from in {401, 403}:
            return {
                "classification": "auth_bypass_via_error",
                "score": 9,
                "reason": "Auth-denied status changed to server error under mutation.",
                "include": True,
            }
        return {
            "classification": "server_error_trigger",
            "score": 7,
            "reason": "Mutation triggered server error.",
            "include": True,
        }

    if status_to in {400, 404} and similarity >= 0.9 and delta <= 180:
        return {
            "classification": "validation_noise",
            "score": 1,
            "reason": "Validation-like 400/404 with highly similar body.",
            "include": True,
        }

    if status_to == 405:
        return {
            "classification": "method_not_allowed",
            "score": 4,
            "reason": "Method not allowed on mutated request.",
            "include": True,
        }

    if status_to == 429:
        return {
            "classification": "rate_limit_triggered",
            "score": 6,
            "reason": "Rate limit triggered by mutation.",
            "include": True,
        }

    if status_to in {403, 406} and similarity >= 0.95:
        return {
            "classification": "waf_block_pattern",
            "score": 3,
            "reason": "WAF/CDN block page detected (high similarity suggests generic block response).",
            "include": True,
        }

    if status_to in {502, 503, 504} and similarity >= 0.9:
        return {
            "classification": "cdn_error_pattern",
            "score": 2,
            "reason": "CDN/gateway error page (likely infrastructure noise, not mutation-specific).",
            "include": True,
        }

    if status_from != status_to:
        return {
            "classification": "status_change",
            "score": 5,
            "reason": f"Status changed from {status_from} to {status_to}.",
            "include": True,
        }

    if redirect_changed:
        return {
            "classification": "redirect_change",
            "score": 4,
            "reason": "Redirect destination changed.",
            "include": True,
        }

    if similarity < 0.7:
        return {
            "classification": "significant_content_change",
            "score": 6,
            "reason": "Body similarity below 0.7 indicates significant content change.",
            "include": True,
        }

    if similarity < 0.96 or delta > 40:
        return {
            "classification": "content_change",
            "score": 3,
            "reason": "Body changed beyond near-identical threshold.",
            "include": True,
        }

    if delta > 10 and delta <= 40:
        return {
            "classification": "minor_content_change",
            "score": 2,
            "reason": f"Minor body length change ({delta} bytes) with same status.",
            "include": True,
        }

    return {
        "classification": "ignore",
        "score": 0,
        "reason": "No material response delta.",
        "include": False,
    }
