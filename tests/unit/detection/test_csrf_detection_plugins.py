import ast
from pathlib import Path
from typing import Any

from src.analysis.passive.detectors.detector_csrf import csrf_protection_checker


def _response(
    url: str,
    body: str,
    headers: dict[str, Any] | None = None,
    *,
    method: str = "GET",
) -> dict[str, Any]:
    return {
        "url": url,
        "status_code": 200,
        "method": method,
        "content_type": "text/html",
        "headers": headers or {},
        "body_text": body,
    }


def test_csrf_checker_reports_state_changing_form_without_token() -> None:
    findings = csrf_protection_checker(
        {"https://app.example.com/profile"},
        [
            _response(
                "https://app.example.com/profile",
                '<form method="post" action="/profile/update">'
                '<input type="text" name="display_name">'
                '<button type="submit">Save</button>'
                "</form>",
                {"Set-Cookie": "session=abc; Secure; HttpOnly"},
            )
        ],
    )

    assert findings
    finding = findings[0]
    assert "form_without_csrf_token" in finding["missing_protections"]
    assert "no_csrf_token" in finding["missing_protections"]
    assert "state_changing_form" in finding["signals"]
    assert finding["unprotected_state_changing_forms"] == 1


def test_csrf_checker_does_not_treat_cookie_flags_as_token_protection() -> None:
    findings = csrf_protection_checker(
        {"https://app.example.com/account/update"},
        [
            _response(
                "https://app.example.com/account/update",
                "<html><body>Account settings</body></html>",
                {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"},
            )
        ],
    )

    assert findings
    assert "no_csrf_token" in findings[0]["missing_protections"]
    assert "no_samesite_cookie" not in findings[0]["missing_protections"]


def test_csrf_checker_allows_representative_protected_form_fixture() -> None:
    findings = csrf_protection_checker(
        {"https://app.example.com/settings"},
        [
            _response(
                "https://app.example.com/settings",
                '<form method="post" action="/settings">'
                '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
                '<input type="text" name="display_name">'
                "</form>",
                {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"},
            )
        ],
    )

    assert findings == []


def test_csrf_plugin_wiring_is_ast_parseable_and_auto_discoverable() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    bindings = repo_root / "src" / "analysis" / "plugin_runtime" / "_bindings.py"
    specs = repo_root / "src" / "analysis" / "plugins" / "_main.py"
    active_probe = repo_root / "src" / "analysis" / "active" / "injection" / "csrf.py"

    for path in (bindings, specs, active_probe):
        ast.parse(path.read_text(encoding="utf-8"))

    binding_source = bindings.read_text(encoding="utf-8")
    spec_source = specs.read_text(encoding="utf-8")
    assert (
        '"csrf_protection_checker": _binding(\n            "urls_and_responses"' in binding_source
    )
    assert "csrf_protection_checker" in spec_source
    assert "csrf_active_probe" in spec_source
