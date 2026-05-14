"""Archive providers package (Wayback, CommonCrawl).

These providers are archive-index focused implementations that return
normalized URL sets. Keeping them in a small subpackage helps group
archive-related code and simplifies navigation.
"""

from . import (
    commoncrawl,  # noqa: F401
    wayback,  # noqa: F401
)

__all__ = ["wayback", "commoncrawl"]
