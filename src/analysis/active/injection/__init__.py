"""Active injection probes for security testing.

Contains probes for path traversal, command injection, XXE, SSRF,
open redirect, CRLF injection, host header injection, SSTI, NoSQL
injection, and deserialization testing.

This package modularizes the injection probes into separate files
for better maintainability and AI-agent editability.
"""

from .command_injection import command_injection_active_probe
from .crlf import crlf_injection_probe
from .csrf import csrf_active_probe
from .deserialization import deserialization_probe
from .grafana_ssrf import detect_grafana, scan_grafana_ssrf
from .host_header import host_header_injection_probe
from .jwt_manipulation import jwt_manipulation_probe
from .ldap import ldap_injection_active_probe
from .nosql import nosql_injection_probe
from .open_redirect import open_redirect_active_probe
from .parameter_pollution import hpp_active_probe
from .path_traversal import path_traversal_active_probe
from .proxy_ssrf import proxy_ssrf_probe
from .ssrf import ssrf_active_probe
from .ssti import ssti_active_probe
from .websocket_hijacking import websocket_hijacking_probe
from .xpath import xpath_injection_active_probe
from .xxe import xxe_active_probe

__all__ = [
    "path_traversal_active_probe",
    "command_injection_active_probe",
    "xxe_active_probe",
    "ssrf_active_probe",
    "grafana_ssrf",
    "proxy_ssrf_probe",
    "open_redirect_active_probe",
    "crlf_injection_probe",
    "host_header_injection_probe",
    "ssti_active_probe",
    "nosql_injection_probe",
    "deserialization_probe",
    "ldap_injection_active_probe",
    "csrf_active_probe",
    "xpath_injection_active_probe",
    "hpp_active_probe",
    "jwt_manipulation_probe",
    "websocket_hijacking_probe",
    "detect_grafana",
    "scan_grafana_ssrf",
]
