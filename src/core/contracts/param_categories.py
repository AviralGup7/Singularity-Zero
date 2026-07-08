"""Shared parameter category enum for cross-module consistency."""

from enum import StrEnum


class ParamCategory(StrEnum):
    SSRF = "ssrf"
    REDIRECT = "redirect"
    LFI = "lfi"
    SQLI = "sqli"
    SSTI = "ssti"
    IDOR = "idor"
    XSS = "xss"
    API_KEY = "api_key"
    OAUTH = "oauth"
    JWT = "jwt"
    GRAPHQL = "graphql"
    UPLOAD = "upload"
    DESERIALIZATION = "deserialization"
    RCE = "rce"
    OPEN_REDIRECT = "open_redirect"
    AUTH_BYPASS = "auth_bypass"
    BUSINESS_LOGIC = "business_logic"
    RATE_LIMIT = "rate_limit"
    HEADER_INJECTION = "header_injection"
    SSRF_OOB = "ssrf_oob"
