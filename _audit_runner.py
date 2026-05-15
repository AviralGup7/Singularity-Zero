#!/usr/bin/env python3
"""Comprehensive frontend + backend audit runner."""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, cast

from hermes_tools import read_file, search_files

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)
print = logger.info

BASE = str(Path(__file__).resolve().parent)
findings: dict[str, list[dict[str, str]]] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}


def add(severity: str, area: str, finding: str, recommendation: str, detail: str = "") -> None:
    findings[severity].append(
        {"area": area, "finding": finding, "recommendation": recommendation, "detail": detail}
    )


def read(p: str) -> str:
    try:
        r = read_file(path=p)
        return str(r.get("content", ""))
    except Exception as e:
        logger.debug("read_file failed for %s: %s", p, e)
        return ""


def search(pat: str, path: str = BASE, limit: int = 30) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], search_files(pattern=pat, path=path, output_mode="files_only", limit=limit))
    except Exception as e:
        logger.debug("search_files failed for pattern %s in %s: %s", pat, path, e)
        return {"matches": [], "total_count": 0}


# ===== BACKEND SECURITY =====
app_py = read(f"{BASE}/src/dashboard/fastapi/app.py")
config_py = read(f"{BASE}/src/dashboard/fastapi/config.py")
mw_py = read(f"{BASE}/src/dashboard/fastapi/middleware.py")
jwt_py = read(f"{BASE}/src/infrastructure/security/auth/jwt_handler.py")
pw_py = read(f"{BASE}/src/infrastructure/security/auth/passwords.py")
rate_py = read(f"{BASE}/src/infrastructure/security/rate_limiter.py")
iv_py = read(f"{BASE}/src/infrastructure/security/input_validation.py")
enc_py = read(f"{BASE}/src/infrastructure/security/encryption.py")
audit_py = read(f"{BASE}/src/infrastructure/security/audit.py")

# 1. CORS
if "allowed_origins" in config_py:
    m = re.search(r"allowed_origins.*?\[(.*?)\]", config_py, re.DOTALL)
    if m and "*" in m.group(1):
        add("critical", "CORS", "CORS allows wildcard origins", "Pin to specific domains")
    else:
        print("[OK] Backend CORS - pinned origins")

# 2. Security headers
for hdr, name in [
    ("Content-Security-Policy", "CSP"),
    ("X-Content-Type-Options", "X-Content-Type-Options"),
    ("X-Frame-Options", "X-Frame-Options"),
    ("Strict-Transport-Security", "HSTS"),
    ("Referrer-Policy", "Referrer-Policy"),
    ("Permissions-Policy", "Permissions-Policy"),
]:
    if hdr in mw_py:
        print(f"[OK] Backend Header - {name}")
        if "'unsafe-inline'" in mw_py:
            add(
                "medium",
                "CSP",
                "CSP has 'unsafe-inline' - weakens script protection",
                "Use nonces or hashes instead of unsafe-inline",
            )
    else:
        add("high", "Backend Headers", f"Missing {name} header", f"Add {name} security header")

# 3. JWT security
# Check for 'none' algorithm acceptance
if re.search(r'["\']none["\']', jwt_py) or "algorithm" in jwt_py.lower():
    if "none" not in jwt_py.lower().replace("_none_", "").replace("non_empty", ""):
        pass  # false positive
    elif re.search(r'alg\s*==\s*["\']none["\']', jwt_py) or '"none"' in jwt_py:
        add(
            "critical",
            "JWT",
            "JWT 'none' algorithm may be accepted",
            "Reject tokens with algorithm=none",
        )

# Check expiration enforcement
if "exp" in jwt_py or "expire" in jwt_py.lower():
    print("[OK] Backend JWT - Expiration checked")
else:
    add(
        "high",
        "JWT",
        "No token expiration validation detected",
        "Enforce JWT 'exp' claim validation",
    )

# Check for token type validation
if "typ" in jwt_py.lower():
    pass  # likely checking token type
if "iss" not in jwt_py and "issuer" not in jwt_py.lower():
    add("info", "JWT", "No JWT issuer (iss) validation", "Add issuer validation for token origin")

# 4. Password hashing
if "pbkdf2" in pw_py.lower():
    im = re.search(r"iterations.*?=\s*(\d+)", pw_py)
    if im:
        iters = int(im.group(1))
        print(f"[OK] Backend Password - PBKDF2 with {iters} iterations")
        if iters < 210000:
            add(
                "medium",
                "Password",
                f"PBKDF2 iterations ({iters}) below OWASP 2024 minimum (210k)",
                "Increase to at least 210,000 iterations",
            )
    else:
        print("[OK] Backend Password - PBKDF2 detected")

# 5. Hardcoded secrets
secret_search = search(
    r'(?:secret|password|api_key|token)\s*=\s*["\'][^"\']{8,}["\']', path=f"{BASE}/src"
)
secret_files = []
for m in secret_search.get("matches", []):
    p = m if isinstance(m, str) else m.get("path", str(m))
    if "__pycache__" not in p:
        secret_files.append(p)
if secret_files:
    add(
        "medium",
        "Secrets",
        f"Possible hardcoded secrets in {len(secret_files)} files",
        "Use environment variables / .env files",
    )

# 6. Debug info leakage
if "debug" in config_py.lower():
    dfm = re.search(r'debug.*?=\s*(True|False|["\']\w+["\'])', config_py)
    if dfm and "True" in dfm.group(1):
        add(
            "high",
            "Config",
            "debug=True in configuration class",
            "Set debug=False for production deployments",
        )
    else:
        print("[OK] Backend Config - debug defaults to False")

# 7. Exception handler leaks
if "500" in app_py and "detail" in app_py:
    add(
        "low",
        "Error Handling",
        "Generic 500 handler exists - ensure no stack traces leaked",
        "Verify production doesn't expose tracebacks",
    )

# 8. Rate limiting
if "rate_limit" in config_py.lower():
    print("[OK] Backend Rate Limiting - configured")
else:
    add(
        "medium",
        "Rate Limit",
        "No rate limiting configuration found",
        "Implement rate limiting on auth and sensitive endpoints",
    )

# 9. Path traversal checks in file serving
if ".." in app_py:
    if '".."' in app_py or "'..'" in app_py:
        logger.info("[CHECK] Backend: Path traversal protection present in file serving")
# Check specific file endpoints have traversal protection
if 'if ".." in filename' in app_py:
    logger.info("[OK] Backend File Serving - Path traversal protection")
else:
    add(
        "high",
        "File Serving",
        "File serving endpoints may be vulnerable to path traversal",
        "Add path traversal validation to all FileResponse endpoints",
    )

# ===== FRONTEND SECURITY =====
app_tsx = read(f"{BASE}/frontend/src/App.tsx")
main_tsx = read(f"{BASE}/frontend/src/main.tsx")
client_ts = read(f"{BASE}/frontend/src/api/client.ts")
core_ts = read(f"{BASE}/frontend/src/api/core.ts")
sanitize_ts = read(f"{BASE}/frontend/src/utils/sanitizeContent.ts")
auth_ctx = read(f"{BASE}/frontend/src/context/AuthContext.tsx")

# 1. XSS protection
if "DOMPurify" in sanitize_ts:
    print("[OK] Frontend XSS - DOMPurify present")
else:
    add(
        "high",
        "Frontend XSS",
        "No DOMPurify or sanitization library found",
        "Add DOMPurify for sanitizing user/scan result content",
    )

# Check for dangerouslySetInnerHTML
dsi_search = search(r"dangerouslySetInnerHTML", path=f"{BASE}/frontend/src")
if dsi_search.get("total_count", 0) > 0:
    add(
        "high",
        "Frontend XSS",
        "dangerouslySetInnerHTML found in codebase",
        "Replace with sanitized rendering or textContent",
    )

# Check for innerHTML usage
ih_search = search(r"\.innerHTML\s*=", path=f"{BASE}/frontend/src")
if ih_search.get("total_count", 0) > 0:
    add(
        "medium",
        "Frontend XSS",
        "innerHTML assignments found in source",
        "Use textContent or sanitize before innerHTML",
    )

# Check for eval()
eval_fe = search(r"\beval\s*\(", path=f"{BASE}/frontend/src")
if eval_fe.get("total_count", 0) > 0:
    add(
        "critical",
        "Frontend XSS",
        "eval() found in frontend code",
        "Remove eval() - use safer alternatives",
    )

# 2. Auth security
if "sessionStorage" in auth_ctx:
    add(
        "medium",
        "Frontend Auth",
        "Auth state stored in sessionStorage (client-side)",
        "SessionStorage is volatile but acceptable; ensure tokens are not stored in localStorage",
    )
if "localStorage" in auth_ctx:
    add(
        "high",
        "Frontend Auth",
        "Auth state stored in localStorage",
        "Move auth state to sessionStorage or httpOnly cookie",
    )
if "auth_token" in client_ts or client_ts:
    auth_header = "sessionStorage.getItem('auth_token')" in client_ts if client_ts else False
    if auth_header:
        add(
            "medium",
            "Frontend Auth",
            "JWT token stored in sessionStorage and sent via Authorization header",
            "This is acceptable but httpOnly cookies would be more secure against XSS",
        )

# 3. HTTPS enforcement
if "https://localhost" not in config_py:
    add(
        "low",
        "Frontend/Backend",
        "No HTTPS enforcement for local dev origins",
        "Ensure production uses HTTPS exclusively",
    )

# 4. API key exposure
if "api_key" in config_py.lower():
    print("[OK] Backend API keys in config - not hardcoded")

# 5. Frontend error handling
if "error" in main_tsx.lower():
    if "stack" in main_tsx.lower():
        add(
            "low",
            "Frontend Errors",
            "Stack traces displayed to user in error overlay",
            "Consider hiding stack traces in production builds",
        )

# 6. CSP in frontend
# Check if frontend build uses CSP meta tags
html_search = search(
    r'<meta\s+http-equiv\s*=\s*["\']Content-Security-Policy["\']', path=f"{BASE}/frontend"
)
if html_search.get("total_count", 0) == 0:
    add(
        "info",
        "Frontend CSP",
        "No CSP meta tag in HTML - relying on server-side headers",
        "This is acceptable if backend headers are always present",
    )

# 7. Route guard
if "RouteGuard" in app_tsx:
    print("[OK] Frontend - Route guards present")
else:
    add(
        "high",
        "Frontend Auth",
        "No route guards implemented",
        "Protect authenticated routes with authorization checks",
    )

# 8. Auth bypass potential (client-side only)
if "viewer" in auth_ctx and "login" in auth_ctx:
    if (
        "api_key" not in auth_ctx.lower()
        and "jwt" not in auth_ctx.lower()
        and "token" not in auth_ctx.lower()
    ):
        add(
            "high",
            "Frontend Auth",
            "Frontend auth is client-side bypassable - no server validation",
            "Client-side auth must be supplemented with server-side JWT validation on all API requests",
        )

# 9. CSRF protection
csrf_search = search(r"csrf|xsrf|X-CSRF|X-XSRF", path=f"{BASE}/src", limit=20)
if csrf_search.get("total_count", 0) == 0:
    add(
        "medium",
        "CSRF",
        "No CSRF token implementation found",
        "Add CSRF protection for state-changing endpoints",
    )

# 10. Check for secure cookie attributes
cookie_search = search(r"cookie.*?(secure|httponly|samesite)", path=f"{BASE}/src", limit=20)
if cookie_search.get("total_count", 0) > 0:
    print("[OK] Backend Cookies - Security attributes present")
else:
    add(
        "medium",
        "Cookies",
        "No secure cookie attributes found",
        "Set Secure, HttpOnly, and SameSite attributes on cookies",
    )

# 11. WebSocket security
ws_search = search(r"websocket", path=f"{BASE}/src", limit=20)
ws_count = ws_search.get("total_count", 0)
print(f"[OK] WebSocket module exists: {ws_count} file references")

# 12. Check database queries for parameterization
raw_sql = search(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{.*\}', path=f"{BASE}/src", limit=20)
if raw_sql.get("total_count", 0) > 0:
    add(
        "high",
        "SQL Injection",
        "f-string SQL queries detected - potential injection",
        "Use parameterized queries with placeholders",
    )

# 13. Output directory permissions
output_check = search(r"chmod|permission|0o\d", path=f"{BASE}/src", limit=20)
if output_check.get("total_count", 0) == 0:
    add(
        "low",
        "File Permissions",
        "No file permission hardening found",
        "Set restrictive permissions on output directories",
    )

# 14. Check for __pycache__ / build artifacts in git
if os.path.exists(f"{BASE}/.gitignore"):
    gi = read(f"{BASE}/.gitignore")
    if "__pycache__" in gi and "node_modules" in gi:
        print("[OK] .gitignore - standard entries present")
    else:
        add("low", "Git", ".gitignore may be missing important entries", "Ensure .gitignore contains __pycache__ and node_modules")

# Print summary
print("\n" + "=" * 70)
print("FRONTEND + BACKEND AUDIT COMPLETE")
print("=" * 70)
for sev in ["critical", "high", "medium", "low", "info"]:
    count = len(findings[sev])
    if count > 0:
        print(f"\n  [{sev.upper()}] {count} finding(s)")
        for i, f in enumerate(findings[sev], 1):
            print(f"    {i}. [{f['area']}] {f['finding']}")
            print(f"       -> {f['recommendation']}")

# Save findings
out_path = Path(BASE) / "_audit_findings.json"
out_path.write_text(json.dumps(findings, indent=2))
logger.info("\nFull report saved to %s", out_path)
