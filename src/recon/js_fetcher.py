"""HTTP fetch helpers for JS endpoint discovery.

Small wrapper around `requests.get` tuned for the JS discovery use-case.
"""

from __future__ import annotations

import requests

from src.core.utils.url_validation import is_safe_url


def _fetch_text_content(url: str, timeout_seconds: int, max_bytes: int) -> str:
    if not is_safe_url(url):
        return ""
    try:
        # SSRF hardening: do NOT auto-follow redirects. ``requests`` would
        # otherwise follow a 302 from an attacker-controlled host to
        # internal metadata endpoints (e.g. 169.254.169.254) without
        # re-validating each hop against ``is_safe_url``. Follow up to
        # 5 redirects manually, re-checking every Location.
        current_url = url
        max_redirects = 5
        for _ in range(max_redirects + 1):
            response = requests.get(
                current_url,
                timeout=max(2, timeout_seconds),  # nosec B113
                allow_redirects=False,
                headers={"User-Agent": "target-specific-pipeline/2.0"},
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    return ""
                # Resolve relative redirects against the previous URL
                next_url = requests.compat.urljoin(current_url, location)
                if not is_safe_url(next_url):
                    return ""
                current_url = next_url
                continue
            if response.status_code >= 400:
                return ""
            content_type = str(response.headers.get("content-type", "")).lower()
            if content_type and not any(
                token in content_type
                for token in ("text", "html", "javascript", "json", "ecmascript")
            ):
                return ""
            body = response.text or ""
            return body[: max(4096, max_bytes)]
        return ""
    except requests.RequestException:
        return ""
