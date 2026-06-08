"""Shared utilities for JWT attack modules."""

import base64
import hashlib
import hmac
import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from src.analysis._core.http_request import _safe_request

logger = logging.getLogger(__name__)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

JWT_AUTH_HEADERS = [
    "Authorization",
    "X-Access-Token",
    "X-Auth-Token",
    "X-JWT-Token",
    "X-Api-Token",
]

# Inline fallback list - always available even if the packaged wordlist is missing.
WEAK_SECRETS: list[bytes] = [
    b"secret",
    b"password",
    b"123456",
    b"key",
    b"jwt",
    b"jwt_secret",
    b"jwt-secret",
    b"jwt-secret-key",
    b"jwt_secret_key",
    b"jwttoken",
    b"mysecret",
    b"my-secret",
    b"my_secret",
    b"my-secret-key",
    b"super-secret",
    b"supersecret",
    b"super_secret",
    b"secretkey",
    b"secret_key",
    b"secret-key",
    b"SecretKey",
    b"SECRET_KEY",
    b"access",
    b"access-token",
    b"access_token",
    b"accessToken",
    b"auth",
    b"auth_token",
    b"authToken",
    b"authentication",
    b"authorization",
    b"token",
    b"Token",
    b"TOKEN",
    b"changeme",
    b"change-me",
    b"change_me",
    b"ChangeMe",
    b"test",
    b"test123",
    b"testing",
    b"default",
    b"default_secret",
    b"default-secret",
    b"defaultsecret",
    b"dev",
    b"development",
    b"development-secret",
    b"dev-secret",
    b"staging",
    b"staging-secret",
    b"prod",
    b"production",
    b"production-secret",
    b"prod-secret",
    b"admin",
    b"administrator",
    b"Admin",
    b"admin123",
    b"administrator123",
    b"Admin123",
    b"root",
    b"root123",
    b"toor",
    b"superuser",
    b"super",
    b"super-admin",
    b"super_admin",
    b"superadmin",
    b"demo",
    b"example",
    b"example-secret",
    b"foobar",
    b"foo",
    b"bar",
    b"baz",
    b"qwerty",
    b"abc123",
    b"letmein",
    b"welcome",
    b"welcome1",
    b"pass",
    b"pass123",
    b"password123",
    b"Password123",
    b"p@ssw0rd",
    b"P@ssw0rd",
    b"P@ssword1",
    b"P@$$w0rd",
    b"1q2w3e4r",
    b"1qaz2wsx",
    b"zaq12wsx",
    b"trustno1",
    b"monkey",
    b"dragon",
    b"shadow",
    b"master",
    b"michael",
    b"jennifer",
    b"111111",
    b"000000",
    b"654321",
    b"666666",
    b"121212",
    b"696969",
    b"777777",
    b"888888",
    b"999999",
    b"abcdef",
    b"abcdefg",
    b"abcd1234",
    b"abcd",
    b"secret1",
    b"secret123",
    b"signing",
    b"signing_key",
    b"signing-key",
    b"signingKey",
    b"SigningKey",
    b"SIGNING_KEY",
    b"hmac",
    b"hmac-key",
    b"hmac_key",
    b"hmacKey",
    b"hmac-secret",
    b"hmac_secret",
    b"hmacSecret",
    b"token-secret",
    b"token_secret",
    b"tokenSecret",
    b"api-secret",
    b"api_secret",
    b"apiSecret",
    b"apisecret",
    b"ApiSecret",
    b"app-secret",
    b"app_secret",
    b"appSecret",
    b"application-secret",
    b"application_secret",
    b"applicationSecret",
    b"app-key",
    b"app_key",
    b"appKey",
    b"AppKey",
    b"service-secret",
    b"service_secret",
    b"serviceSecret",
    b"server-secret",
    b"server_secret",
    b"serverSecret",
    b"session",
    b"session-secret",
    b"session_secret",
    b"sessionSecret",
    b"cookie-secret",
    b"cookie_secret",
    b"cookieSecret",
    b"web-secret",
    b"web_secret",
    b"webSecret",
    b"client-secret",
    b"client_secret",
    b"clientSecret",
    b"ClientSecret",
    b"private",
    b"private-key",
    b"private_key",
    b"privateKey",
    b"PrivateKey",
    b"PRIVATE_KEY",
    b"public",
    b"public-key",
    b"public_key",
    b"publicKey",
    b"PublicKey",
    b"PUBLIC_KEY",
    b"key-secret",
    b"key_secret",
    b"keySecret",
    b"key123",
    b"key1234",
    b"key-pass",
    b"key_pass",
    b"keyPass",
    b"keypass",
    b"passphrase",
    b"pass-phrase",
    b"pass_phrase",
    b"master-key",
    b"master_key",
    b"masterKey",
    b"MasterKey",
    b"master-secret",
    b"master_secret",
    b"masterSecret",
    b"MasterSecret",
    b"encryption-key",
    b"encryption_key",
    b"encryptionKey",
    b"EncryptionKey",
    b"decryption-key",
    b"decryption_key",
    b"decryptionKey",
    b"DecryptionKey",
    b"jwt-key",
    b"jwt_key",
    b"jwtKey",
    b"JwtKey",
    b"JWT_KEY",
    b"JWT_SECRET",
    b"jwtSecret",
    b"JWTSecret",
    b"jwt-private-key",
    b"jwt_private_key",
    b"jwtPrivateKey",
    b"JwtPrivateKey",
    b"JWT_PRIVATE_KEY",
    b"jwt-public-key",
    b"jwt_public_key",
    b"jwtPublicKey",
    b"JwtPublicKey",
    b"JWT_PUBLIC_KEY",
    b"token-key",
    b"token_key",
    b"tokenKey",
    b"TokenKey",
    b"auth-key",
    b"auth_key",
    b"authKey",
    b"AuthKey",
    b"auth-secret",
    b"auth_secret",
    b"authSecret",
    b"AuthSecret",
    b"api-key",
    b"api_key",
    b"apiKey",
    b"ApiKey",
    b"API_KEY",
    b"api-token",
    b"api_token",
    b"apiToken",
    b"ApiToken",
    b"session-key",
    b"session_key",
    b"sessionKey",
    b"SessionKey",
    b"cookie-key",
    b"cookie_key",
    b"cookieKey",
    b"CookieKey",
    b"keyboard_cat",
    b"keyboardcat",
    b"shhh",
    b"shhhh",
    b"s3cr3t",
    b"s3cret",
    b"s3cr3t!",
    b"S3cr3t",
    b"S3cret",
    b"S3CR3T",
    b"topsecret",
    b"top-secret",
    b"top_secret",
    b"topSecret",
    b"TopSecret",
    b"TOP_SECRET",
    b"classified",
    b"confidential",
    b"restricted",
    b"internal",
    b"internal-secret",
    b"internal_secret",
    b"internalSecret",
    b"InternalSecret",
    b"company-secret",
    b"company_secret",
    b"companySecret",
    b"CompanySecret",
    b"my-super-secret",
    b"my_super_secret",
    b"mySuperSecret",
    b"this-is-a-secret",
    b"this_is_a_secret",
    b"thisIsASecret",
    b"ThisIsASecret",
    b"your-secret-key",
    b"your_secret_key",
    b"yourSecretKey",
    b"YourSecretKey",
    b"YOUR_SECRET_KEY",
    b"your-256-bit-secret",
    b"your_256_bit_secret",
    b"your256bitsecret",
    b"Your256BitSecret",
    b"YOUR_256_BIT_SECRET",
    b"your-32-byte-secret",
    b"your_32_byte_secret",
    b"your32bytesecret",
    b"Your32ByteSecret",
    b"azure",
    b"azure-secret",
    b"azure_secret",
    b"azureSecret",
    b"aws",
    b"aws-secret",
    b"aws_secret",
    b"awsSecret",
    b"amazon",
    b"amazon-secret",
    b"amazon_secret",
    b"amazonSecret",
    b"gcp",
    b"gcp-secret",
    b"gcp_secret",
    b"gcpSecret",
    b"google",
    b"google-secret",
    b"google_secret",
    b"googleSecret",
    b"microsoft",
    b"microsoft-secret",
    b"microsoft_secret",
    b"microsoftSecret",
    b"django",
    b"django-secret",
    b"django_secret",
    b"djangoSecret",
    b"DjangoSecret",
    b"DJANGO_SECRET_KEY",
    b"flask",
    b"flask-secret",
    b"flask_secret",
    b"flaskSecret",
    b"FlaskSecret",
    b"FLASK_SECRET_KEY",
    b"express",
    b"express-secret",
    b"express_secret",
    b"expressSecret",
    b"ExpressSecret",
    b"EXPRESS_SECRET",
    b"spring",
    b"spring-secret",
    b"spring_secret",
    b"springSecret",
    b"SpringSecret",
    b"laravel",
    b"laravel-secret",
    b"laravel_secret",
    b"laravelSecret",
    b"LaravelSecret",
    b"LARAVEL_SECRET",
    b"rails",
    b"rails-secret",
    b"rails_secret",
    b"railsSecret",
    b"RailsSecret",
    b"RAILS_SECRET",
    b"symfony",
    b"symfony-secret",
    b"symfony_secret",
    b"symfonySecret",
    b"fastapi",
    b"fastapi-secret",
    b"fastapi_secret",
    b"fastapiSecret",
    b"FastAPISecret",
    b"nestjs",
    b"nestjs-secret",
    b"nestjs_secret",
    b"nestjsSecret",
    b"NestJSSecret",
    b"00000000000000000000000000000000",
    b"11111111111111111111111111111111",
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    b"ffffffffffffffffffffffffffffffff",
    b"deadbeefdeadbeefdeadbeefdeadbeef",
    b"cafebabecafebabecafebabecafebabe",
    b"0123456789abcdef0123456789abcdef",
    b"1234567890abcdef1234567890abcdef",
    b"abcdef0123456789abcdef0123456789",
    b"notsosecret",
    b"not-so-secret",
    b"not_so_secret",
    b"notSoSecret",
    b"NotSoSecret",
    b"NOT_SO_SECRET",
    b"thisisasecret",
    b"this-is-a-secret",
    b"this_is_a_secret",
    b"thisIsASecret",
    b"ThisIsASecret",
    b"THIS_IS_A_SECRET",
    b"thisismysecret",
    b"this-is-my-secret",
    b"this_is_my_secret",
    b"thisIsMySecret",
    b"ThisIsMySecret",
    b"THIS_IS_MY_SECRET",
    b"pleasedontguess",
    b"please-dont-guess",
    b"please_dont_guess",
    b"pleaseDontGuess",
    b"PleaseDontGuess",
    b"PLEASE_DONT_GUESS",
    b"youshallnotpass",
    b"you-shall-not-pass",
    b"you_shall_not_pass",
    b"youShallNotPass",
    b"YouShallNotPass",
    b"YOU_SHALL_NOT_PASS",
    b"letmeinplease",
    b"let-me-in-please",
    b"let_me_in_please",
    b"letMeInPlease",
    b"LetMeInPlease",
    b"asdf",
    b"asdfasdf",
    b"qwer",
    b"qwerqwer",
    b"zxcv",
    b"zxcvzxcv",
    b"1q2w3e",
    b"1q2w3e4r5t",
    b"q1w2e3r4",
    b"poiuy",
    b"mnbvcxz",
    b"lkjhgf",
]

WORDLIST_FILENAME = "jwt-secrets.txt"
WORDLIST_MAX_ENTRIES = 50000


@lru_cache(maxsize=1)
def _load_wordlist_bytes(path_str: str) -> tuple[bytes, ...]:
    """Load weak-JWT secrets from a packaged wordlist file.

    Returns an empty tuple if the file is missing or unreadable so the
    caller can fall back to the inline ``WEAK_SECRETS`` list.
    """
    try:
        path = Path(path_str)
        if not path.is_file():
            return ()
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("Could not read JWT wordlist %s: %s", path_str, exc)
        return ()

    out: list[bytes] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(out) >= WORDLIST_MAX_ENTRIES:
            break
        out.append(stripped.encode("utf-8"))
    return tuple(out)


def get_weak_secrets() -> list[bytes]:
    """Return the full weak-secret list: packaged wordlist + inline fallback.

    The packaged wordlist (``data/jwt-secrets.txt``) takes precedence when
    available; ``WEAK_SECRETS`` is always merged in last to guarantee a
    minimum baseline coverage even with a stripped build.
    """
    here = Path(__file__).resolve().parent
    wordlist_path = here / "data" / WORDLIST_FILENAME
    from_wordlist = list(_load_wordlist_bytes(str(wordlist_path)))
    seen: set[bytes] = set(from_wordlist)
    merged = list(dict.fromkeys(from_wordlist))
    for secret in WEAK_SECRETS:
        if secret not in seen:
            seen.add(secret)
            merged.append(secret)
    return merged


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _decode_jwt_part(part: str) -> dict | Any | None:
    try:
        decoded = _b64url_decode(part)
        return json.loads(decoded)
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def _create_jwt(header: dict, payload: dict, secret: bytes) -> str:
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _extract_jwt(url: str, session: Any) -> str | None:
    for header_name in JWT_AUTH_HEADERS:
        if hasattr(session, "headers") and header_name in session.headers:
            val = session.headers[header_name]
            if isinstance(val, str) and val.startswith("Bearer "):
                val = val[7:]
            match = JWT_RE.match(val)
            if match:
                return cast(str, val)
    return None


def _get_original_status(url: str, session: Any) -> int:
    try:
        if hasattr(session, "get"):
            resp = session.get(url, timeout=8, verify=True)
            return cast(int, resp.status_code)
        return cast(int, _safe_request(url, timeout=8).get("status", 0))
    except Exception as e:
        logger.debug("Failed to fetch original status for %s: %s", url, e)
        return 0


def _send_with_token(url: str, token: str, auth_header: str, session: Any) -> dict[str, Any]:
    try:
        if hasattr(session, "request"):
            resp = session.request(
                "GET",
                url,
                headers={auth_header: f"Bearer {token}"},
                timeout=10,
                verify=True,
            )
            return {
                "status": resp.status_code,
                "body": resp.text[:8000],
                "headers": dict(resp.headers),
                "success": resp.status_code < 400,
            }
        headers = {auth_header: f"Bearer {token}"}
        return _safe_request(url, headers=headers, timeout=10)
    except Exception as e:
        logger.debug("JWT request failed: %s", e)
        return {"status": 0, "body": "", "headers": {}, "success": False, "error": str(e)}
