"""CRLF URL query parameter variant generation."""

from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from ._crlf_constants import CRLF_APPEND_SUFFIXES, CRLF_ESCAPE_SEQUENCES, CRLF_PROBE_PAYLOADS


def _build_payload(crlf_seq: str, payload_template: str, token: str) -> str:
    """Build a concrete CRLF payload from template, escape sequence, and token."""
    space = "%20"
    return payload_template.format(crlf=crlf_seq, space=space, token=token)


def generate_crlf_variants(
    base_url: str,
    param_index: int,
    param_name: str,
    token: str,
) -> list[dict[str, Any]]:
    """Generate a matrix of URL variants for CRLF injection testing.

    Combines every escape sequence with every payload template and every
    append suffix to produce a comprehensive set of test URLs.

    Args:
        base_url: The original URL to probe.
        param_index: Index of the parameter to inject into.
        param_name: Name of the parameter to inject into.
        token: Unique token for this probe round.

    Returns:
        List of dicts with keys: url, variant_name, payload, expected_header, expected_value.
    """
    parsed = urlparse(base_url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not query_pairs or param_index >= len(query_pairs):
        return []

    variants: list[dict[str, Any]] = []

    for escape_entry in CRLF_ESCAPE_SEQUENCES:
        escape_name = next(iter(escape_entry))
        crlf_seq = escape_entry[escape_name]

        for payload_spec in CRLF_PROBE_PAYLOADS:
            payload_name = payload_spec["name"]
            template = payload_spec["template"]

            raw_payload = _build_payload(crlf_seq, template, token)

            for suffix in CRLF_APPEND_SUFFIXES:
                full_value = raw_payload + suffix

                updated = list(query_pairs)
                updated[param_index] = (param_name, full_value)
                test_url = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

                expected_header = ""
                expected_value = ""
                if payload_name == "set_cookie":
                    expected_header = "set-cookie"
                    expected_value = f"crlf={token}"
                elif payload_name == "arbitrary_header":
                    expected_header = "x-crlf-test"
                    expected_value = f"detected-{token}"
                elif payload_name == "location_redirect":
                    expected_header = "location"
                    expected_value = f"https://evil-{token}.com"
                elif payload_name == "x_forwarded_for":
                    expected_header = "x-forwarded-for"
                    expected_value = f"127.0.0.{token}"
                elif payload_name == "custom_header_simple":
                    expected_header = "x-custom-test"
                    expected_value = f"probed-{token}"
                elif payload_name == "double_crlf_header":
                    expected_header = "x-crlf-double"
                    expected_value = f"injected-{token}"
                elif payload_name == "authorization_inject":
                    expected_header = "authorization"
                    expected_value = f"Bearer crlf-{token}"
                elif payload_name == "refresh_header":
                    expected_header = "refresh"
                    expected_value = f"0;url=https://evil-{token}.com"
                elif payload_name == "response_split":
                    expected_header = ""
                    expected_value = f"crlf-body-{token}"

                variant_name = f"{payload_name}:{escape_name}"
                if suffix:
                    variant_name += f":+{quote(suffix, safe='')}"

                variants.append(
                    {
                        "url": test_url,
                        "variant_name": variant_name,
                        "payload": full_value,
                        "param_name": param_name,
                        "expected_header": expected_header,
                        "expected_value": expected_value,
                        "crlf_seq": crlf_seq,
                        "injection_point": "param",
                    }
                )

    return variants
