"""Subdomain enumeration from external source integrations."""

from .rapiddns import query_rapiddns
from .virustotal import query_virustotal_passive

__all__ = [
    "query_virustotal_passive",
    "query_rapiddns",
]
