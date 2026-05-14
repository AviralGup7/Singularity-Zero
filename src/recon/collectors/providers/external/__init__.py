"""External providers package (URLScan, OTX).

These providers call third-party search APIs and are grouped to make
their network and rate-limit behaviour easier to find.
"""

from . import (
    otx,  # noqa: F401
    urlscan,  # noqa: F401
)

__all__ = ["urlscan", "otx"]
