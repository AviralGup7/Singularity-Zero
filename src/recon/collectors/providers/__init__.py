"""Providers for in-house collectors.

Each provider implements a small, well-tested interface that returns a
set of normalized URLs and a metadata dictionary describing the fetch.
"""

from . import simplecrawler as crawler  # noqa: F401
from .archive import (
    commoncrawl,  # noqa: F401
    wayback,  # noqa: F401
)
from .external import (
    otx,  # noqa: F401
    urlscan,  # noqa: F401
)

__all__ = ["wayback", "commoncrawl", "crawler", "urlscan", "otx"]
