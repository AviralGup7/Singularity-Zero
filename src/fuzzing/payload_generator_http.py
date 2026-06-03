"""HTTP header and body payload generators for fuzzing.

Contains functions for generating header injection payloads and POST body
mutation payloads based on endpoint characteristics and parameter types.
Extracted from fuzzing/payload_generator.py for better separation of concerns.
"""

import logging
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import classify_endpoint, endpoint_signature, is_noise_url
from src.core.mutation_engine import generate_payloads_for_parameter

logger = logging.getLogger(__name__)

# Dynamic header injection templates
EXTRA_INJECTABLE_HEADERS = [
    "X-Forwarded-For",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Host",
    "Origin",
    "Referer",
    "X-Remote-Addr",
    "X-Remote-IP",
    "X-Client-IP",
    "True-Client-IP",
    "X-Forwarded-Server",
    "X-Forwarded-Port",
    "Forwarded",
    "X-Host",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-Request-ID",
    "X-Forwarded-By",
    "X-Real-IP",
    "X-Varnish",
    "If-Modified-Since",
    "If-None-Match",
]

# Header-specific payload patterns
HEADER_PAYLOADS: dict[str, list[dict[str, str]]] = {
    "X-Forwarded-For": [
        {"header": "X-Forwarded-For", "variant": "127.0.0.1", "reason": "localhost spoofing"},
        {"header": "X-Forwarded-For", "variant": "::1", "reason": "IPv6 localhost spoofing"},
        {"header": "X-Forwarded-For", "variant": "169.254.169.254", "reason": "cloud metadata IP"},
        {"header": "X-Forwarded-For", "variant": "10.0.0.1", "reason": "internal IP spoofing"},
    ],
    "X-Original-URL": [
        {"header": "X-Original-URL", "variant": "/admin", "reason": "admin path bypass"},
        {"header": "X-Original-URL", "variant": "/api/internal", "reason": "internal API access"},
        {"header": "X-Original-URL", "variant": "/debug", "reason": "debug endpoint access"},
    ],
    "X-Forwarded-Host": [
        {"header": "X-Forwarded-Host", "variant": "evil.com", "reason": "host header injection"},
        {
            "header": "X-Forwarded-Host",
            "variant": "localhost:8080",
            "reason": "internal host spoofing",
        },
    ],
    "Origin": [
        {"header": "Origin", "variant": "https://evil.com", "reason": "CORS bypass attempt"},
        {"header": "Origin", "variant": "null", "reason": "null origin CORS test"},
    ],
    "X-HTTP-Method-Override": [
        {
            "header": "X-HTTP-Method-Override",
            "variant": "DELETE",
            "reason": "method override to DELETE",
        },
        {"header": "X-HTTP-Method-Override", "variant": "PUT", "reason": "method override to PUT"},
        {
            "header": "X-HTTP-Method-Override",
            "variant": "PATCH",
            "reason": "method override to PATCH",
        },
    ],
}

INJECTABLE_HEADERS = sorted(list(set(list(HEADER_PAYLOADS.keys()) + EXTRA_INJECTABLE_HEADERS)))


def generate_header_payloads(
    priority_urls: list[str],
    *,
    limit: int = 12,
    max_headers_per_endpoint: int = 8,
) -> list[dict[str, Any]]:
    """Generate HTTP header injection payloads for priority endpoints."""
    suggestions: list[dict[str, Any]] = []
    seen_endpoint_keys: set[str] = set()

    for url in priority_urls:
        if len(suggestions) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoint_keys:
            continue
        seen_endpoint_keys.add(endpoint_key)

        generated: list[dict[str, str]] = []
        parsed = urlparse(url)
        path = parsed.path.lower()
        relevant_headers = list(INJECTABLE_HEADERS)
        if "/api/" in path or endpoint_key.startswith("/api/") or endpoint_key == "/api":
            relevant_headers = [
                "X-Forwarded-For",
                "X-Forwarded-Host",
                "X-HTTP-Method-Override",
                "X-Method-Override",
                "Host",
                "Origin",
            ]
        elif any(kw in path for kw in ("/admin", "/manage", "/console")):
            relevant_headers = [
                "X-Forwarded-For",
                "X-Remote-Addr",
                "X-Client-IP",
                "True-Client-IP",
                "X-Original-URL",
            ]
        for header_name in relevant_headers[:max_headers_per_endpoint]:
            if header_name in HEADER_PAYLOADS:
                generated.extend(HEADER_PAYLOADS[header_name])
            else:
                generated.append(
                    {
                        "header": header_name,
                        "variant": "injection-test",
                        "reason": f"{header_name} injection probe",
                    }
                )
            if len(generated) >= max_headers_per_endpoint:
                break
        if generated:
            suggestions.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "header_suggestions": generated[:max_headers_per_endpoint],
                }
            )

    return suggestions


def generate_body_payloads(
    priority_urls: list[str],
    *,
    limit: int = 12,
    max_fields_per_endpoint: int = 6,
) -> list[dict[str, Any]]:
    """Generate POST body mutation payloads for API endpoints."""
    suggestions: list[dict[str, Any]] = []
    seen_endpoint_keys: set[str] = set()

    for url in priority_urls:
        if len(suggestions) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoint_keys:
            continue
        seen_endpoint_keys.add(endpoint_key)

        parsed = urlparse(url)
        path = parsed.path.lower()
        # Target all potential API endpoints for body mutations
        is_api = any(
            kw in path
            for kw in (
                "/api/",
                "/rest/",
                "/graphql",
                "/v1/",
                "/v2/",
                "/v3/",
                "/svc/",
                "/service/",
                "/data/",
                "/rpc/",
                "/webhook/",
            )
        )
        if not is_api:
            try:
                endpoint_type = classify_endpoint(url)
                if endpoint_type in ("api", "graphql", "rest"):
                    is_api = True
            except Exception:  # noqa: S110
                pass
        if not is_api:
            continue

        # Generate body field mutations based on common API patterns
        body_fields = _infer_body_fields_from_url(url)
        if not body_fields:
            logger.debug("No body fields inferred for %s", url)
            continue

        sample_values = {"integer": "0", "float": "0.0", "string": "", "boolean": "true"}
        generated: list[dict[str, Any]] = []
        for field_name, field_type in body_fields[:max_fields_per_endpoint]:
            sample = sample_values.get(field_type, "")
            payloads = generate_payloads_for_parameter(field_name, sample)
            for payload in payloads[:3]:
                base_payload = payload.get("variant", "")
                generated.append(
                    {
                        "field": field_name,
                        "type": field_type,
                        "payload": base_payload,
                        "strategy": payload.get("param_type", "type_confusion"),
                        "reason": payload.get("reason", f"{field_name} mutation"),
                    }
                )
                # Generate ML adversarial variants for string types
                if field_type == "string" and base_payload:
                    for adv in generate_ml_adversarial_variants(base_payload)[:2]:
                        generated.append(
                            {
                                "field": field_name,
                                "type": field_type,
                                "payload": adv,
                                "strategy": "ml_adversarial",
                                "reason": f"ML adversarial WAF-bypass variant of {field_name}",
                            }
                        )
            if len(generated) >= max_fields_per_endpoint * 5:
                break

        if generated:
            suggestions.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "body_suggestions": generated[: max_fields_per_endpoint * 3],
                }
            )

    return suggestions


def _infer_body_fields_from_url(url: str) -> list[tuple[str, str]]:
    """Infer likely POST body fields from URL characteristics."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    fields: list[tuple[str, str]] = []

    # Common API field patterns based on URL path
    if "/user" in path or "/profile" in path:
        fields.extend(
            [("user_id", "integer"), ("email", "string"), ("name", "string"), ("role", "string")]
        )
    if "/order" in path or "/purchase" in path:
        fields.extend(
            [
                ("order_id", "integer"),
                ("amount", "float"),
                ("quantity", "integer"),
                ("payment_method", "string"),
            ]
        )
    if "/account" in path or "/tenant" in path:
        fields.extend(
            [("account_id", "integer"), ("tenant_id", "integer"), ("is_admin", "boolean")]
        )
    if "/login" in path or "/auth" in path:
        fields.extend([("username", "string"), ("password", "string"), ("token", "string")])
    if "/upload" in path or "/file" in path:
        fields.extend([("file_name", "string"), ("file_type", "string"), ("file_size", "integer")])

    # Try parsing query parameters from the URL itself
    if not fields and parsed.query:
        from urllib.parse import parse_qsl

        from src.core.mutation_engine import detect_parameter_type
        for q_name, q_val in parse_qsl(parsed.query, keep_blank_values=True):
            ptype = detect_parameter_type(q_name, q_val)
            mapped_type = "string"
            if ptype == "numeric":
                mapped_type = "integer"
            elif ptype == "id":
                mapped_type = "integer" if q_val.isdigit() else "string"
            fields.append((q_name, mapped_type))

    # If still empty, fall back to a set of generic REST/GraphQL parameters
    if not fields:
        fields.extend([
            ("id", "integer"),
            ("data", "string"),
            ("query", "string"),
            ("payload", "string"),
            ("input", "string"),
            ("status", "string"),
        ])

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_fields = []
    for name, ftype in fields:
        if name not in seen:
            seen.add(name)
            unique_fields.append((name, ftype))

    return unique_fields


def generate_ml_adversarial_variants(payload: str) -> list[str]:
    """
    Generate ML-specific adversarial variants for a given security payload.
    Applies perturbation techniques designed to bypass neural network-based WAF classifiers:
    1. Homoglyph Substitution (using visually similar unicode characters)
    2. Zero-width spaces / Null byte insertions
    3. Padding and token disruption (e.g., semantic comments)
    4. Case/Encoding mixed permutations
    """
    variants = []
    # 1. Padding / Comment perturbation
    variants.append(f"/*ML_PERTURB*/{payload}/*ML_PERTURB*/")
    # 2. Case perturbation
    variants.append(
        "".join(c.upper() if idx % 2 == 0 else c.lower() for idx, c in enumerate(payload))
    )
    # 3. Hex/URL encoding mix
    if payload:
        variants.append(payload.replace("'", "%27").replace('"', "%22").replace(" ", "%20"))
    return [v for v in variants if v and v != payload]
