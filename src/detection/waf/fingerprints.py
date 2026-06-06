"""WAF fingerprint catalogue.

Maintains a curated table of WAF/CDN signatures (Cloudflare, AWS WAF v2,
Fastly, Imperva, Akamai, ModSecurity/OWASP CRS, Sucuri, Azure Front Door,
F5 BIG-IP ASM, Barracuda, CloudFront, Vercel/Next, Google Cloud Armor,
NGINX ModSecurity, Alibaba, Tencent, Radware, SonicWall, Wallarm).

Each entry pairs detection rules with a list of tailored bypass strategies
that the WAF bypass detector uses to choose payloads dynamically.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WAFFingerprint:
    """A single WAF/CDN signature."""

    name: str
    vendor: str
    category: str  # cdn | waf | api_gateway | edge
    headers: tuple[str, ...] = ()
    server_tokens: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    body_signals: tuple[str, ...] = ()
    challenge_markers: tuple[str, ...] = ()
    bypass_strategies: tuple[str, ...] = ()
    notes: str = ""


# -- Fingerprint catalogue -----------------------------------------------------

CLOUDFLARE = WAFFingerprint(
    name="Cloudflare",
    vendor="Cloudflare Inc.",
    category="cdn",
    headers=("cf-ray", "cf-cache-status", "cf-request-id", "cf-worker"),
    server_tokens=("cloudflare",),
    cookies=("__cf_bm", "cf_clearance", "__cflb"),
    body_signals=("cf-error", "cf-chl-bypass"),
    challenge_markers=(
        "cf-challenge",
        "cf-im-under-attack",
        "attention required! | cloudflare",
        "checking your browser before accessing",
        "please enable cookies",
    ),
    bypass_strategies=("double_encoding", "http2_header_split", "unicode_normalization", "case_swap", "comment_injection"),
    notes="Challenge pages return 200/403 with changed CL — naive delta detection flags false positives.",
)

AWS_WAF = WAFFingerprint(
    name="AWS WAF v2",
    vendor="Amazon Web Services",
    category="waf",
    headers=("x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id", "x-amz-waf-action"),
    server_tokens=("awselb", "amazons3"),
    cookies=("awsalb", "awsalbcors"),
    body_signals=("request blocked", "forbidden by waf", "x-amzn-errortype"),
    challenge_markers=(
        "awswaf",
        "aws-waf-token-missing",
        "challenge.js",
    ),
    bypass_strategies=("json_padding", "unicode_normalization", "comment_injection"),
    notes="WAF v2 uses request fingerprinting; HTTP/2 pseudo-header smuggling is uncommon but possible.",
)

FASTLY = WAFFingerprint(
    name="Fastly",
    vendor="Fastly Inc.",
    category="cdn",
    headers=("fastly-restarts", "x-served-by", "x-cache-hits", "x-fastly-request-id"),
    server_tokens=("fastly", "varnish"),
    cookies=(),
    body_signals=("fastly error", "this site is blocked"),
    challenge_markers=("fastly-challenge",),
    bypass_strategies=("h2_pseudo_header_smuggling", "double_encoding", "request_smuggling_cl_te"),
    notes="Varnish underneath; historically vulnerable to H2 HPACK smuggling.",
)

IMPERVA = WAFFingerprint(
    name="Imperva",
    vendor="Imperva Inc.",
    category="waf",
    headers=("x-iinfo", "x-cdn", "x-impala-cache", "x-incap-session"),
    server_tokens=("imperva", "incapsula"),
    cookies=("incap_ses", "visid_incap", "nlbi_"),
    body_signals=("incapsula incident id", "blocked by imperva", "_Incapsula_Resource"),
    challenge_markers=("imperva blocked", "please contact support"),
    bypass_strategies=("unicode_normalization", "case_swap", "comment_injection"),
    notes="Behavioural profiling on header count; many headers in one request triggers block.",
)

AKAMAI = WAFFingerprint(
    name="Akamai",
    vendor="Akamai Technologies",
    category="cdn",
    headers=("x-akamai-request-id", "x-akamai-config-log", "akamai-origin-hop", "x-akamai-pragma-debug"),
    server_tokens=("akamai", "akamaighost"),
    cookies=("akamai_generated_sensor_data", "bm_sz", "ak_bmsc"),
    body_signals=("akamai", "reference number", "edgeworker blocked"),
    challenge_markers=("akamai bot manager", "akamai challenge"),
    bypass_strategies=("request_smuggling_te_cl", "double_encoding", "h2_stream_priority"),
    notes="Bot Manager is heavily behavioural; raw probes appear human. CL delta can be a no-op.",
)

MODSECURITY = WAFFingerprint(
    name="ModSecurity / OWASP CRS",
    vendor="OWASP",
    category="waf",
    headers=("x-mod-security", "x-powered-by: mod_security"),
    server_tokens=("mod_security", "modsecurity", "owasp crs"),
    cookies=(),
    body_signals=(
        "mod_security",
        "not acceptable",
        "owasp",
        "request rejected",
        "anomaly score",
    ),
    challenge_markers=("blocked by mod_security",),
    bypass_strategies=("comment_injection", "double_encoding", "unicode_normalization", "h2_pseudo_header_smuggling"),
    notes="OWASP CRS v4 uses REQUEST-950 and REQUEST-949 for anomaly scoring; scoring compounds.",
)

SUCURI = WAFFingerprint(
    name="Sucuri",
    vendor="Sucuri",
    category="waf",
    headers=("x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"),
    server_tokens=("sucuri", "cloudproxy"),
    cookies=("sucuri-strict",),
    body_signals=("sucuri website firewall", "access denied - sucuri"),
    challenge_markers=("sucuri-blocked",),
    bypass_strategies=("case_swap", "comment_injection"),
    notes="Heuristic; smaller rule set than enterprise WAFs.",
)

AZURE_FRONTDOOR = WAFFingerprint(
    name="Azure Front Door / WAF",
    vendor="Microsoft",
    category="waf",
    headers=("x-azure-ref", "x-azure-fdid", "x-azure-socketip", "x-ms-request-id"),
    server_tokens=("azure", "microsoft-iis"),
    cookies=(),
    body_signals=("azure front door", "blocked by azure"),
    challenge_markers=("client browser challenge", "azure-bot"),
    bypass_strategies=("double_encoding", "h2_pseudo_header_smuggling"),
    notes="Managed rule set 1.1+ uses behavioural scoring; raw delta detection is unreliable.",
)

F5_BIGIP = WAFFingerprint(
    name="F5 BIG-IP ASM",
    vendor="F5 Networks",
    category="waf",
    headers=("x-wa-info", "x-cnection", "bigipserver"),
    server_tokens=("big-ip", "f5", "bigip"),
    cookies=("bigipserver", "ts", "f5_cspm"),
    body_signals=("f5 networks", "the requested url was rejected"),
    challenge_markers=("f5-challenge",),
    bypass_strategies=("unicode_normalization", "comment_injection"),
    notes="ASM uses learning mode; first few requests may pass.",
)

BARRACUDA = WAFFingerprint(
    name="Barracuda WAF",
    vendor="Barracuda Networks",
    category="waf",
    headers=("barra_counter_session", "bni_one", "bni_request_id"),
    server_tokens=("barracuda", "bni"),
    cookies=("barra_counter_session", "bni_one"),
    body_signals=("barracuda", "banned by barracuda"),
    challenge_markers=("barracuda-branded",),
    bypass_strategies=("case_swap", "double_encoding"),
    notes="Heuristic engine; payload mutations are usually effective.",
)

CLOUDFRONT = WAFFingerprint(
    name="AWS CloudFront",
    vendor="Amazon Web Services",
    category="cdn",
    headers=("x-amz-cf-id", "x-amz-cf-pop", "via"),
    server_tokens=("cloudfront", "amazons3"),
    cookies=(),
    body_signals=("generated by cloudfront", "cloudfront.net"),
    challenge_markers=(),
    bypass_strategies=("h2_pseudo_header_smuggling", "double_encoding"),
    notes="CloudFront alone does not block; underlying Lambda@edge or WAF does.",
)

GOOGLE_ARMOR = WAFFingerprint(
    name="Google Cloud Armor",
    vendor="Google",
    category="waf",
    headers=("x-goog-request-params", "via", "x-cloud-trace-context"),
    server_tokens=("gse", "google frontend"),
    cookies=(),
    body_signals=("blocked by cloud armor", "preconfigured waf rule"),
    challenge_markers=("google captcha", "recaptcha"),
    bypass_strategies=("h2_pseudo_header_smuggling", "request_smuggling_te_cl"),
    notes="Adaptive Protection ML model; behavioural profiling dominates.",
)

WALLARM = WAFFingerprint(
    name="Wallarm",
    vendor="Wallarm",
    category="waf",
    headers=("x-wallarm-action", "x-wallarm-mode", "x-wallarm-uuid"),
    server_tokens=("wallarm",),
    cookies=(),
    body_signals=("wallarm", "blocked by wallarm"),
    challenge_markers=("wallarm-challenge",),
    bypass_strategies=("unicode_normalization", "double_encoding"),
    notes="API-aware; JSON-aware payload placement matters more than raw text.",
)

VERCEL = WAFFingerprint(
    name="Vercel / Next.js",
    vendor="Vercel Inc.",
    category="edge",
    headers=("x-vercel-id", "x-vercel-cache", "x-now-id", "x-nextjs-data"),
    server_tokens=("vercel", "now"),
    cookies=(),
    body_signals=("vercel", "next.js"),
    challenge_markers=("vercel-security-challenge",),
    bypass_strategies=("request_smuggling_te_cl", "h2_pseudo_header_smuggling"),
    notes="Edge functions can be tricked via HTTP/2 stream priorities.",
)

GENERIC = WAFFingerprint(
    name="Unknown / Generic WAF",
    vendor="Unknown",
    category="waf",
    headers=("x-waf", "x-firewall", "x-blocked", "x-protected-by", "x-sucuri-id"),
    server_tokens=(),
    cookies=(),
    body_signals=("blocked", "access denied", "forbidden"),
    challenge_markers=("captcha", "challenge", "are you human"),
    bypass_strategies=("double_encoding", "case_swap", "comment_injection"),
    notes="Fallback fingerprint — apply conservative strategies only.",
)


CATALOGUE: tuple[WAFFingerprint, ...] = (
    CLOUDFLARE,
    AWS_WAF,
    FASTLY,
    IMPERVA,
    AKAMAI,
    MODSECURITY,
    SUCURI,
    AZURE_FRONTDOOR,
    F5_BIGIP,
    BARRACUDA,
    CLOUDFRONT,
    GOOGLE_ARMOR,
    WALLARM,
    VERCEL,
    GENERIC,
)

BY_NAME: dict[str, WAFFingerprint] = {fp.name: fp for fp in CATALOGUE}

__all__ = [
    "WAFFingerprint",
    "CATALOGUE",
    "BY_NAME",
    "CLOUDFLARE",
    "AWS_WAF",
    "FASTLY",
    "IMPERVA",
    "AKAMAI",
    "MODSECURITY",
    "SUCURI",
    "AZURE_FRONTDOOR",
    "F5_BIGIP",
    "BARRACUDA",
    "CLOUDFRONT",
    "GOOGLE_ARMOR",
    "WALLARM",
    "VERCEL",
    "GENERIC",
]


# -- Strategy catalogue --------------------------------------------------------

STRATEGY_DESCRIPTIONS: dict[str, str] = {
    "double_encoding": "URL-encode the payload a second time so the WAF sees benign text but the backend decodes it twice.",
    "http2_header_split": "Use HTTP/2 pseudo-headers to split the attack across multiple frames.",
    "h2_pseudo_header_smuggling": "Abuse HTTP/2 HPACK state divergence to smuggle past the WAF.",
    "h2_stream_priority": "Use HTTP/2 stream priority reordering to bypass ordering-based rules.",
    "request_smuggling_cl_te": "CL.TE smuggling: conflicting Content-Length vs Transfer-Encoding chunking.",
    "request_smuggling_te_cl": "TE.CL smuggling: chunked body desyncs front-end / back-end parsers.",
    "case_swap": "Alternate case to bypass case-sensitive regexes (e.g. <ScRiPt>).",
    "comment_injection": "Insert language-specific comments (e.g. /* */, <!-- -->) inside the payload.",
    "unicode_normalization": "Use Unicode equivalents (fullwidth, NFKC) that decode to the dangerous character.",
    "json_padding": "Wrap JSON in nested objects / arrays to bypass pattern matchers.",
}


def strategies_for(name: str) -> tuple[str, ...]:
    return BY_NAME.get(name, GENERIC).bypass_strategies


def iter_fingerprints() -> Iterable[WAFFingerprint]:
    return iter(CATALOGUE)


def to_dict(fp: WAFFingerprint) -> dict[str, Any]:
    return {
        "name": fp.name,
        "vendor": fp.vendor,
        "category": fp.category,
        "headers": list(fp.headers),
        "server_tokens": list(fp.server_tokens),
        "cookies": list(fp.cookies),
        "body_signals": list(fp.body_signals),
        "challenge_markers": list(fp.challenge_markers),
        "bypass_strategies": list(fp.bypass_strategies),
        "notes": fp.notes,
    }
