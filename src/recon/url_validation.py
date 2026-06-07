"""URL-safety helpers re-exported under the recon namespace.

The canonical implementation lives in :mod:`src.core.utils.url_validation`;
this module exists purely so callers can write
``from src.recon.url_validation import is_safe_url`` without coupling
to the core module path. Re-exporting preserves a single source of
truth while keeping the recon-facing API compact.
"""

from __future__ import annotations

from src.core.utils.url_validation import (
    is_safe_url,
    is_safe_url_with_dns_check,
)

__all__ = ["is_safe_url", "is_safe_url_with_dns_check"]
