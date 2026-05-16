import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

# API surface checkers extracted to _api_surface.py
from src.analysis.checks.exposure._api_surface import (
    graphql_error_leakage_checker,
    graphql_introspection_exposure_checker,
    grpc_reflection_exposure_checker,
    openapi_swagger_spec_checker,
)
from src.analysis.helpers import classify_endpoint, meaningful_query_pairs, normalize_headers
from src.analysis.passive.extended_shared import (
    STACK_RE,
    _get_email_re,
    _get_third_party_key_patterns,
    record,
    scan_urls_and_responses,
)

__all__ = [
    "api_version_disclosure_checker",
    "backup_file_exposure_checker",
    "cache_poisoning_indicator_checker",
    "cdn_waf_fingerprint_gap_checker",
    "cloud_storage_exposure_checker",
    "csp_weakness_analyzer",
    "dns_misconfiguration_signal_checker",
    "email_leakage_detector",
    "environment_file_exposure_checker",
    "error_stack_trace_detector",
    "graphql_error_leakage_checker",
    "graphql_introspection_exposure_checker",
    "grpc_reflection_exposure_checker",
    "hsts_weakness_checker",
    "http_method_exposure_checker",
    "locale_debug_toggle_checker",
    "log_file_exposure_checker",
    "openapi_swagger_spec_checker",
    "parameter_pollution_indicator_checker",
    "password_confirmation_checker",
    "public_repo_exposure_checker",
    "rate_limit_header_analyzer",
    "referrer_policy_weakness_checker",
    "service_worker_misconfiguration_checker",
    "subdomain_takeover_indicator_checker",
    "third_party_key_exposure_checker",
    "websocket_endpoint_discovery",
]


def cloud_storage_exposure_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    cloud_hosts = (
        ".googleapis.com",
        ".storage.cloud.google.com",
        ".s3.amazonaws.com",
        ".s3.",
        ".amazonaws.com",
        ".storage.googleapis.com",
        ".storage.cloud.google.com",
        ".blob.core.windows.net",
        ".file.core.windows.net",
        ".digitaloceanspaces.com",
        ".r2.dev",
        ".backblazeb2.com",
        ".cloudflarestorage.com",
    )
    bucket_tokens = (
        "<ListBucketResult",
        "<Contents>",
        "NoSuchBucket",
        "BucketName",
        "BlobNotFound",
        "ListBucketResult",
        "AccessDenied",
        "AnonymousUser",
        "x-amz-request-id",
        "x-amz-id-2",
        "PublicAccess",
        "Anonymous access is not allowed",
        "The specified bucket does not exist",
    )
    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=lambda url: any(token in url.lower() for token in cloud_hosts),
        response_matcher=lambda r: any(
            token in (r.get("body_text") or "")[:12000] for token in bucket_tokens
        ),
        url_indicator="cloud_storage_host",
        response_indicator="bucket_listing_or_error",
        limit=80,
    )


def subdomain_takeover_indicator_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    patterns = (
        "there isn't a github pages site here",
        "github pages",
        "no such app",
        "herokucdn",
        "herokuapp.com",
        "no such bucket",
        "the specified bucket does not exist",
        "NoSuchBucket",
        "azurewebsites.net",
        "blob.core.windows.net",
        "404 web site not found",
        "fastly error: unknown domain",
        "fastly",
        "domain not claimed",
        "pages.dev",
        "sorry, this shop is currently unavailable",
        "shopify",
        "there's nothing here",
        "tumblr",
        "do you want to register",
        "wordpress",
        "repository not found",
        "bitbucket",
        "project not found",
        "surge",
        "the gods are wise",
        "pantheon",
        "smugmug",
        "we could not find what you're looking for",
        "helpjuice",
        "helpscoutdocs",
        "404 page not found",
        "tilda",
        "uservoice.com",
        "myjetbrains",
        "cargo.site",
        "readme.io",
        "but if you're looking to build your own website",
        "strikingly",
        "404 - page not found",
        "webflow",
        "launchrock",
        "announcekit",
    )
    return scan_urls_and_responses(
        urls,
        responses,
        response_matcher=lambda r: any(
            token in (r.get("body_text") or "").lower()[:12000] for token in patterns
        ),
        response_indicator="dangling_service_indicator",
        limit=40,
    )


def service_worker_misconfiguration_checker(
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings = []
    for response in responses:
        url = str(response.get("url", ""))
        headers = normalize_headers(response)
        body = response.get("body_text") or ""
        if (
            "service-worker" not in url.lower()
            and "serviceworker" not in body.lower()
            and "service-worker-allowed" not in headers
        ):
            continue
        issues = []
        allowed = headers.get("service-worker-allowed", "")
        if allowed in {"", "/"}:
            issues.append("broad_service_worker_scope")
        if "cache.addall" in body.lower() or "skipwaiting(" in body.lower():
            issues.append("aggressive_service_worker_caching")
        if issues:
            findings.append(record(url, status_code=response.get("status_code"), issues=issues))
    return findings[:40]


def csp_weakness_analyzer(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for response in responses:
        url = str(response.get("url", ""))
        headers = normalize_headers(response)
        csp = headers.get("content-security-policy", "")
        if not csp:
            continue
        lowered = csp.lower()
        issues = []
        if "'unsafe-inline'" in lowered:
            issues.append("unsafe_inline")
        if "'unsafe-eval'" in lowered:
            issues.append("unsafe_eval")
        if "*" in lowered:
            issues.append("wildcard_source")
        if "object-src" not in lowered:
            issues.append("missing_object_src")
        if "frame-ancestors" not in lowered:
            issues.append("missing_frame_ancestors")
        if issues:
            findings.append(
                record(url, status_code=response.get("status_code"), issues=issues, csp=csp[:300])
            )
    return findings[:80]


def referrer_policy_weakness_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    weak = {"unsafe-url", "origin", "origin-when-cross-origin", "no-referrer-when-downgrade"}
    for response in responses:
        headers = normalize_headers(response)
        policy = headers.get("referrer-policy", "").strip().lower()
        if policy in weak:
            findings.append(
                record(
                    str(response.get("url", "")),
                    status_code=response.get("status_code"),
                    policy=policy,
                    issues=["permissive_referrer_policy"],
                )
            )
    return findings[:60]


def hsts_weakness_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for response in responses:
        url = str(response.get("url", ""))
        if not url.startswith("https://"):
            continue
        headers = normalize_headers(response)
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            continue
        lowered = hsts.lower()
        issues = []
        match = re.search(r"max-age=(\d+)", lowered)
        if match and int(match.group(1)) < 31536000:
            issues.append("low_hsts_max_age")
        if "includesubdomains" not in lowered:
            issues.append("missing_include_subdomains")
        if issues:
            findings.append(
                record(url, status_code=response.get("status_code"), issues=issues, hsts=hsts)
            )
    return findings[:60]


def dns_misconfiguration_signal_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    patterns = {
        "weak_spf_all": re.compile(r"\bv=spf1\b[^\n]{0,200}\s\+all\b", re.IGNORECASE),
        "missing_dmarc_hint": re.compile(r"\bspf\b|\bdkim\b", re.IGNORECASE),
        "zone_debug_hint": re.compile(
            r"\bdig\b|\bnslookup\b|\bzone transfer\b|\baxfr\b", re.IGNORECASE
        ),
    }
    for response in responses:
        body = (response.get("body_text") or "")[:12000]
        hits = [label for label, pattern in patterns.items() if pattern.search(body)]
        if hits:
            findings.append(
                record(
                    str(response.get("url", "")),
                    status_code=response.get("status_code"),
                    indicators=hits,
                )
            )
    return findings[:40]


def email_leakage_detector(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    email_re = _get_email_re()
    if email_re is None:
        return findings
    for response in responses:
        body = (response.get("body_text") or "")[:12000]
        emails = sorted(
            {
                match.group(0).lower()
                for match in email_re.finditer(body)
                if not match.group(0).lower().endswith((".png", ".jpg"))
            }
        )
        if emails:
            findings.append(
                record(
                    str(response.get("url", "")),
                    status_code=response.get("status_code"),
                    emails=emails[:12],
                )
            )
    return findings[:80]


def api_version_disclosure_checker(urls: set[str]) -> list[dict[str, Any]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    findings = []
    for url in sorted(urls):
        parsed = urlparse(url)
        match = re.search(r"/v(\d+)(?:/|$)", parsed.path.lower())
        if not match:
            continue
        grouped[f"{parsed.netloc.lower()}|{parsed.path.lower().split(match.group(0))[0]}"].add(
            f"v{match.group(1)}"
        )
    for key, versions in grouped.items():
        if len(versions) >= 2:
            host, _ = key.split("|", 1)
            findings.append(
                record(host, indicator="multiple_api_versions_exposed", versions=sorted(versions))
            )
    return findings[:40]


def error_stack_trace_detector(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect stack traces and verbose error messages in responses."""
    findings = []
    for response in responses:
        body = (response.get("body_text") or "")[:12000]
        if STACK_RE.search(body):
            findings.append(
                record(
                    str(response.get("url", "")),
                    status_code=response.get("status_code"),
                    indicator="stack_trace_or_verbose_error",
                )
            )
    return findings[:80]


def rate_limit_header_analyzer(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for response in responses:
        url = str(response.get("url", ""))
        headers = {
            str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
        }
        relevant = {
            key: value
            for key, value in headers.items()
            if "ratelimit" in key
            or key in {"retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"}
        }
        endpoint_type = classify_endpoint(url)
        is_form_like = any(
            token in url.lower()
            for token in ("/login", "/signin", "/signup", "/register", "/password", "/reset")
        )
        issues = []
        if (endpoint_type in {"API", "AUTH"} or is_form_like) and not relevant:
            issues.append("missing_rate_limit_headers")
        if issues:
            findings.append(record(url, status_code=response.get("status_code"), issues=issues))
    return findings[:80]


def password_confirmation_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    findings = []
    form_hints = ("signup", "register", "password", "reset", "change-password", "create-account")

    for response in responses:
        url = str(response.get("url", ""))
        lowered_url = url.lower()
        if not any(token in lowered_url for token in form_hints):
            continue
        body = (response.get("body_text") or "")[:12000].lower()
        if "password" not in body:
            continue
        has_confirmation = any(
            token in body
            for token in (
                "confirm_password",
                "password_confirmation",
                "confirm password",
                'name="confirm',
            )
        )
        if not has_confirmation:
            findings.append(
                record(
                    url,
                    status_code=response.get("status_code"),
                    issues=["missing_password_confirmation_field"],
                )
            )

    seen = {item["url"] for item in findings}
    for url in sorted(urls):
        lowered = url.lower()
        if url in seen:
            continue
        if (
            any(token in lowered for token in ("signup", "register", "create-account"))
            and "confirm" not in lowered
        ):
            findings.append(record(url, indicator="signup_path_without_confirmation_hint"))
        if len(findings) >= 80:
            break
    return findings[:80]


def cache_poisoning_indicator_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for response in responses:
        url = str(response.get("url", ""))
        headers = normalize_headers(response)
        cache_control = headers.get("cache-control", "").lower()
        vary = headers.get("vary", "").lower()
        body = (response.get("body_text") or "")[:12000].lower()
        issues = []
        if "public" in cache_control and "no-store" not in cache_control:
            if "host" not in vary and "x-forwarded-host" in body:
                issues.append("public_cache_without_host_vary")
            if "x-forwarded-host" in body or "x-host" in body:
                issues.append("host_header_reflection_in_cacheable_response")
            if "x-forwarded-proto" in body or "x-forwarded-scheme" in body:
                issues.append("forwarded_proto_reflection_in_cacheable_response")
        if issues:
            findings.append(
                record(url, status_code=response.get("status_code"), issues=sorted(set(issues)))
            )
    return findings[:80]


def public_repo_exposure_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    repo_patterns = (
        "/.git/",
        "/.git/config",
        "/.git/HEAD",
        "/.git/refs",
        "/.svn/",
        "/.hg/",
    )
    repo_tokens = (
        "git-upload-pack",
        "git-receive-pack",
        "ref: refs/heads/",
        "src.core.repositoryformatversion",
        "svn:entry",
        "hg-revlog",
    )
    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=lambda url: any(token in url.lower() for token in repo_patterns),
        response_matcher=lambda r: any(
            token in (r.get("body_text") or "")[:4000].lower() for token in repo_tokens
        ),
        url_indicator="repo_metadata_path",
        response_indicator="repo_contents_exposed",
        limit=80,
    )


def cdn_waf_fingerprint_gap_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_host: dict[str, set[str]] = defaultdict(set)
    for response in responses:
        url = str(response.get("url", ""))
        host = urlparse(url).netloc.lower()
        headers = " ".join(
            f"{str(k).lower()}:{str(v).lower()}" for k, v in (response.get("headers") or {}).items()
        )
        markers = set()
        if "cloudflare" in headers or "cf-ray" in headers:
            markers.add("cloudflare")
        if "akamai" in headers:
            markers.add("akamai")
        if "x-amz-cf-id" in headers:
            markers.add("cloudfront")
        if "x-sucuri" in headers:
            markers.add("sucuri")
        if not markers:
            markers.add("unprotected")
        by_host[host].update(markers)
    findings = []
    for host, markers in by_host.items():
        if "unprotected" in markers:
            findings.append(record(host, indicator="no_cdn_waf_protection"))
        else:
            findings.append(record(host, indicator="cdn_waf_fingerprints", markers=sorted(markers)))
    return findings[:60]


def backup_file_exposure_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    backup_extensions = (
        ".bak",
        ".old",
        ".backup",
        ".orig",
        ".save",
        ".swp",
        ".swo",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".rar",
        ".7z",
        ".log",
        ".tmp",
        ".temp",
        ".copy",
        ".bkp",
        ".dist",
        ".example",
        ".sql",
        ".dump",
        ".db",
        ".sqlite",
        ".sqlite3",
    )
    backup_patterns = (
        "backup",
        "bak",
        "old",
        "copy",
        "save",
        "archive",
        "database",
        "db_",
        "dump",
        "export",
        "config.bak",
        "config.old",
        "config.backup",
        "wp-config",
        "database.sql",
        "dump.sql",
    )

    def is_backup_url(url: str) -> bool:
        url_lower = url.lower()
        if any(url_lower.endswith(ext) or ext + "?" in url_lower for ext in backup_extensions):
            return True
        if any(pattern in url_lower for pattern in backup_patterns):
            return True
        return False

    def is_backup_response(r: dict[str, Any]) -> bool:
        status_code = int(r.get("status_code") or 0)
        if status_code >= 400:
            return False
        url = str(r.get("url", ""))
        body = (r.get("body_text") or "")[:4000].lower()
        backup_indicators = (
            "create table",
            "insert into",
            "drop table",
            "alter table",
            "pkzip",
            "rar!",
            "7z",
            "sqlite format",
            "backup created",
            "dump completed",
            "database backup",
            "sql dump",
            "/* mysql",
            "/* postgres",
        )
        if any(ind in body for ind in backup_indicators):
            return True
        return is_backup_url(url)

    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=is_backup_url,
        response_matcher=is_backup_response,
        url_indicator="backup_file_path",
        response_indicator="backup_file_accessible",
        limit=80,
    )


def environment_file_exposure_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    env_paths = (
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.staging",
        "/.env.test",
        "/.env.backup",
        "/.env.example",
        "/.env.old",
        "/.env.save",
        "config.js",
        "config.json",
        "secrets",
        "credentials",
    )
    env_tokens = ("DB_PASSWORD=", "AWS_SECRET_ACCESS_KEY", "APP_ENV=", "DATABASE_URL=")
    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=lambda url: any(token in url.lower() for token in env_paths),
        response_matcher=lambda r: any(
            token in (r.get("body_text") or "")[:8000] for token in env_tokens
        ),
        url_indicator="env_or_config_path",
        response_indicator="env_file_contents",
        limit=80,
    )


def log_file_exposure_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    log_extensions = (
        ".log",
        ".trace",
        ".debug",
        ".out",
        ".err",
        ".access_log",
        ".error_log",
        ".access.log",
        ".error.log",
        ".log.1",
        ".log.2",
        ".log.3",
        ".log.bak",
        ".txt",
        ".csv",
        ".json",
    )
    log_paths = (
        "/logs",
        "/log",
        "/debug",
        "/trace",
        "/var/log",
        "/tmp/log",  # nosec: S108
        "/app/log",
        "/access.log",
        "/error.log",
        "/debug.log",
        "/application.log",
        "/server.log",
        "/api.log",
        "/wp-content/debug.log",
        "/storage/logs",
    )
    log_patterns = (
        r"\b(INFO|WARN|WARNING|ERROR|DEBUG|CRITICAL|FATAL)\b.+\d{4}-\d{2}-\d{2}",
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
        r"\b(GET|POST|PUT|DELETE|PATCH)\s+/\S+\s+\d{3}\b",
        r"\btraceback\b.+\bline\s+\d+\b",
        r"\bstack\s*trace\b",
        r"\bexception\b.+\bat\s+\S+\.\S+\(",
        r"\bSQL\b.+\b(SELECT|INSERT|UPDATE|DELETE)\b",
        r"\brequest_id\b.+\b[A-Fa-f0-9-]{36}\b",
    )
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in log_patterns]

    def is_log_url(url: str) -> bool:
        url_lower = url.lower()
        if any(url_lower.endswith(ext) or ext + "?" in url_lower for ext in log_extensions):
            return True
        if any(path in url_lower for path in log_paths):
            return True
        return False

    def is_log_response(r: dict[str, Any]) -> bool:
        body = (r.get("body_text") or "")[:8000]
        if any(pattern.search(body) for pattern in compiled_patterns):
            return True
        return is_log_url(str(r.get("url", "")))

    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=is_log_url,
        response_matcher=is_log_response,
        url_indicator="log_path_hint",
        response_indicator="log_content_pattern",
        limit=80,
    )


def websocket_endpoint_discovery(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    ws_tokens = ("/ws", "/websocket", "socket.io")
    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=lambda url: (
            url.lower().startswith(("ws://", "wss://"))
            or any(token in url.lower() for token in ws_tokens)
        ),
        response_matcher=lambda r: _has_websocket_upgrade(r),
        url_indicator="websocket_endpoint_hint",
        response_indicator="websocket_upgrade_hint",
        limit=80,
    )


def _has_websocket_upgrade(response: dict[str, Any]) -> bool:
    headers = {
        str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
    }
    return (
        "upgrade" in headers.get("connection", "").lower()
        or headers.get("upgrade", "").lower() == "websocket"
    )


def http_method_exposure_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    risky = {"put", "delete", "patch", "trace", "connect"}
    for response in responses:
        headers = {
            str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
        }
        allow = headers.get("allow", "") or headers.get("public", "")
        if not allow:
            continue
        methods = {part.strip().upper() for part in allow.split(",") if part.strip()}
        risky_methods = sorted(method for method in methods if method.lower() in risky)
        if risky_methods:
            findings.append(
                record(
                    str(response.get("url", "")),
                    status_code=response.get("status_code"),
                    methods=sorted(methods),
                    risky_methods=risky_methods,
                )
            )
    return findings[:80]


def parameter_pollution_indicator_checker(urls: set[str]) -> list[dict[str, Any]]:
    findings = []
    for url in sorted(urls):
        names = [name for name, _ in meaningful_query_pairs(url)]
        duplicates = sorted({name for name in names if names.count(name) >= 2})
        if duplicates:
            findings.append(
                record(url, duplicate_parameters=duplicates, indicator="duplicate_query_parameters")
            )
    return findings[:80]


def locale_debug_toggle_checker(urls: set[str]) -> list[dict[str, Any]]:
    findings = []
    debug_like = {"debug", "trace", "test", "preview", "dev", "locale", "lang", "environment"}
    for url in sorted(urls):
        hits = [
            name
            for name, value in meaningful_query_pairs(url)
            if name in debug_like and (value or name)
        ]
        if hits:
            findings.append(record(url, indicators=sorted(set(hits))))
    return findings[:80]


def third_party_key_exposure_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    tpp = _get_third_party_key_patterns()
    for response in responses:
        body = (response.get("body_text") or "")[:12000]
        for _label, pattern in tpp:
            matches = pattern.findall(body)
            if matches:
                findings.append(
                    record(
                        str(response.get("url", "")),
                        status_code=response.get("status_code"),
                        keys_found=[m[0] if isinstance(m, tuple) else m for m in matches[:5]],
                    )
                )
                break
    return findings[:80]
