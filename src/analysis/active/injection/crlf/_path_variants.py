"""CRLF path variant generation for URLs without query parameters."""

from typing import Any
from urllib.parse import urlparse, urlunparse

from ._crlf_constants import CRLF_ESCAPE_SEQUENCES, CRLF_PROBE_PAYLOADS


def _build_payload(crlf_seq: str, payload_template: str, token: str) -> str:
    """Build a concrete CRLF payload from template, escape sequence, and token."""
    space = "%20"
    return payload_template.format(crlf=crlf_seq, space=space, token=token)


def generate_path_variants(
    base_url: str,
    token: str,
) -> list[dict[str, Any]]:
    """Generate CRLF payload variants injected into the URL PATH.

    Used when the URL has no query parameters. Appends
    /{starting_string}{escape}{injection} to the path.

    Args:
        base_url: The URL to probe.
        token: Unique probe token.

    Returns:
        List of dicts with url, variant_name, payload, expected_header, expected_value, crlf_seq.
    """
    parsed = urlparse(base_url)
    path = parsed.path.rstrip("/")

    variants: list[dict[str, Any]] = []
    starting_strings = ["", "crlf", "test", "redirect", "next"]

    for escape_entry in CRLF_ESCAPE_SEQUENCES:
        escape_name = next(iter(escape_entry))
        crlf_seq = escape_entry[escape_name]

        for payload_spec in CRLF_PROBE_PAYLOADS:
            payload_name = payload_spec["name"]
            template = payload_spec["template"]

            for start in starting_strings:
                raw_payload = _build_payload(crlf_seq, template, token)
                injected_path = f"{path}/{start}{raw_payload}"
                test_url = urlunparse(parsed._replace(path=injected_path))

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
                elif payload_name == "response_split":
                    expected_value = f"crlf-body-{token}"

                variant_name = f"path:{payload_name}:{escape_name}"
                if start:
                    variant_name += f":+{start}"

                variants.append(
                    {
                        "url": test_url,
                        "variant_name": variant_name,
                        "payload": raw_payload,
                        "param_name": "__PATH__",
                        "expected_header": expected_header,
                        "expected_value": expected_value,
                        "crlf_seq": crlf_seq,
                        "injection_point": "path",
                    }
                )

    return variants
