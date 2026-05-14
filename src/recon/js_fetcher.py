"""HTTP fetch helpers for JS endpoint discovery.

Small wrapper around `requests.get` tuned for the JS discovery use-case.
"""

from __future__ import annotations

import requests


def _fetch_text_content(url: str, timeout_seconds: int, max_bytes: int) -> str:
    try:
        response = requests.get(
            url,
            timeout=max(2, timeout_seconds),
            allow_redirects=True,
            headers={"User-Agent": "target-specific-pipeline/2.0"},
        )
        if response.status_code >= 400:
            return ""
        content_type = str(response.headers.get("content-type", "")).lower()
        if content_type and not any(
            token in content_type for token in ("text", "html", "javascript", "json", "ecmascript")
        ):
            return ""
        body = response.text or ""
        return body[: max(4096, max_bytes)]
    except requests.RequestException:
        return ""
