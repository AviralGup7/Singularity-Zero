"""Validation results section rendering for pipeline reports.

Generates HTML sections displaying validation results including API key
reviews, token replay findings, and callback receiver status.
"""

import html
from typing import Any

AUTHORIZED_API_KEY_REVIEW_CHECKS = [
    "Use the key in a direct API request in an authorized test environment and compare the response with the unauthenticated baseline.",
    "Check sensitive routes such as /users, /orders, and /admin only where you have explicit permission to validate access boundaries.",
    "Repeat the request without cookies or session state to confirm whether the key alone is sufficient.",
    "Validate source restrictions only from approved network locations and managed test devices.",
    "Change object identifiers in a controlled dataset to verify that tenant or user boundaries still hold.",
    "Replay the same request several times to confirm rate-limit behavior and alerting.",
    "Try the same key only across in-scope subdomains or services to confirm scope boundaries.",
    "Review admin-oriented or privilege-changing flows in a non-production environment before concluding the key has elevated rights.",
    "Compare allowed HTTP methods for the same resource and note any write-capable paths.",
    "Record response deltas with and without the key, including status, body shape, and payload size.",
    "Check invalid or expired formats to understand validation and error handling behavior.",
    "Compare browser and script-based requests in an approved environment to spot client-side enforcement differences.",
    "Confirm whether create, update, or delete operations are accepted before treating the exposure as read-only.",
    "Test whether the key is honored in headers, query parameters, or both, and document the accepted patterns.",
    "Review whether extra parameters such as user_id or token change authorization outcomes on approved test data.",
]


def validation_results_section(summary: dict[str, Any]) -> str:
    meta = summary.get("validation_meta", {})
    results = summary.get("validation_results", {})
    callback_context = meta.get("callback_context", {})
    token_replay = meta.get("token_replay", {})
    overview = [
        f"Callback receiver: {html.escape(str(callback_context.get('status', 'unknown')))}",
        f"Callback state: {html.escape(str(callback_context.get('validation_state', 'passive_only')))}",
        f"Callback provider: {html.escape(str(callback_context.get('provider', 'none')))}",
        f"Token exposures queued: {html.escape(str(token_replay.get('count', 0)))}",
        f"Grouped token endpoints: {html.escape(str(len(token_replay.get('grouped_by_endpoint', []))))}",
        f"High replay JWTs: {html.escape(str(len(token_replay.get('high_replay_jwt_targets', []))))}",
    ]
    rows = [f"<p class='muted'>{' | '.join(overview)}</p>"]
    for label, items in results.items():
        if not items:
            rows.append(
                f"<h3>{html.escape(label.replace('_', ' '))}</h3><p class='muted'>No results.</p>"
            )
            continue
        if label == "api_key_validation":
            rendered_items = []
            for item in items[:8]:
                candidate = item.get("candidate", {}) or {}
                totals = item.get("totals", {}) or {}
                rendered_items.append(
                    "<li>"
                    f"<strong>{html.escape(str(candidate.get('masked_key', 'masked key')))}</strong><br>"
                    f"<span class='muted'>{html.escape(str(candidate.get('provider', 'unknown')))} | {html.escape(str(candidate.get('source_type', 'unknown')))} | base {html.escape(str(candidate.get('base_url', 'n/a')))}</span><br>"
                    f"<span class='muted'>checks {html.escape(str(totals.get('checks_run', 0)))} | risks {html.escape(str(totals.get('risk_count', 0)))} | ok {html.escape(str(totals.get('ok_count', 0)))}</span>"
                    "</li>"
                )
            rows.append(
                f"<h3>{html.escape(label.replace('_', ' '))}</h3><ul>{''.join(rendered_items)}</ul>"
            )
            continue
        rendered_items = [f"<li>{html.escape(str(item))}</li>" for item in items[:20]]
        rendered_items_html: str = "".join(rendered_items)
        rows.append(
            f"<h3>{html.escape(label.replace('_', ' '))}</h3><ul>{rendered_items_html}</ul>"
        )
    return f"<section><h2>Built-In Validation Results</h2>{''.join(rows)}</section>"


def exposed_api_keys_section(
    summary: dict[str, Any], analysis_results: dict[str, list[dict[str, Any]]]
) -> str:
    token_replay = (summary.get("validation_meta", {}) or {}).get("token_replay", {}) or {}
    token_targets = token_replay.get("grouped_by_endpoint", []) or []
    third_party_findings = analysis_results.get("third_party_key_exposure_checker", []) or []
    api_key_validation = (summary.get("validation_results", {}) or {}).get(
        "api_key_validation", []
    ) or []
    if not token_targets and not third_party_findings and not api_key_validation:
        return "<section><h2>Exposed API Keys</h2><p class='muted'>No exposed API key or token findings were summarized for this run.</p></section>"

    checklist = html.escape(
        "\n".join(
            f"{index}. {item}"
            for index, item in enumerate(AUTHORIZED_API_KEY_REVIEW_CHECKS, start=1)
        ),
        quote=True,
    )
    rows = []

    for item in token_targets[:20]:
        severity = str(item.get("severity", "medium")).lower()
        tone = "bad" if severity == "high" else "warn" if severity == "medium" else "ok"
        evidence = ", ".join(item.get("indicators", [])) or "token"
        location = str(item.get("location", "unknown")).replace("_", " ")
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(item.get('url', '') or 'n/a')}</code></td>"
            "<td>Token leak detector</td>"
            f"<td>{html.escape(location)}</td>"
            f"<td>{html.escape(evidence)}</td>"
            f"<td><span class='ui-badge {tone}'>{html.escape(severity)}</span></td>"
            "<td>"
            f"<button type='button' class='action-btn show-api-key-checklist' data-target-label='{html.escape(item.get('url', '') or 'n/a', quote=True)}' data-exposure-type='token exposure' data-review-checklist='{checklist}'>Review Checklist</button>"
            "</td>"
            "</tr>"
        )

    for item in third_party_findings[:20]:
        indicators = ", ".join(item.get("indicators", [])) or "third-party key"
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(item.get('url', '') or 'n/a')}</code></td>"
            "<td>Third-party key exposure</td>"
            "<td>response body</td>"
            f"<td>{html.escape(indicators)}</td>"
            "<td><span class='ui-badge warn'>medium</span></td>"
            "<td>"
            f"<button type='button' class='action-btn show-api-key-checklist' data-target-label='{html.escape(item.get('url', '') or 'n/a', quote=True)}' data-exposure-type='third-party key exposure' data-review-checklist='{checklist}'>Review Checklist</button>"
            "</td>"
            "</tr>"
        )

    for item in api_key_validation[:12]:
        candidate = item.get("candidate", {}) or {}
        totals = item.get("totals", {}) or {}
        risk_count = int(totals.get("risk_count", 0))
        tone = "bad" if risk_count else "ok"
        evidence = f"checks {totals.get('checks_run', 0)} | risks {risk_count}"
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(candidate.get('source_url', '') or 'n/a'))}</code></td>"
            "<td>Active API key validation</td>"
            f"<td>{html.escape(str(candidate.get('placement', 'unknown')))}</td>"
            f"<td>{html.escape(evidence)}</td>"
            f"<td><span class='ui-badge {tone}'>{html.escape('high' if risk_count else 'ok')}</span></td>"
            "<td>"
            f"<button type='button' class='action-btn show-api-key-checklist' data-target-label='{html.escape(str(candidate.get('masked_key', 'masked key')), quote=True)}' data-exposure-type='executed api key checks' data-review-checklist='{html.escape(_format_api_key_results(item), quote=True)}'>View Results</button>"
            "</td>"
            "</tr>"
        )

    overview_bits = [
        f"Token endpoints: {html.escape(str(len(token_targets)))}",
        f"Third-party key hits: {html.escape(str(len(third_party_findings)))}",
        f"Active key validations: {html.escape(str(len(api_key_validation)))}",
        "Buttons open either the review checklist or the executed key-validation summary.",
    ]
    table = (
        "<div class='table-wrap'>"
        "<table class='report-table'>"
        "<thead><tr><th>URL</th><th>Source</th><th>Location</th><th>Evidence</th><th>Risk</th><th>Review</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
        "</div>"
    )
    return f"<section><h2>Exposed API Keys</h2><p class='muted'>{' | '.join(overview_bits)}</p>{table}</section>"


def _format_api_key_results(item: dict[str, Any]) -> str:
    lines = []
    candidate = item.get("candidate", {}) or {}
    lines.append(f"Key: {candidate.get('masked_key', 'masked key')}")
    lines.append(f"Provider: {candidate.get('provider', 'unknown')}")
    lines.append(f"Base URL: {candidate.get('base_url', 'n/a')}")
    lines.append("")
    for check in item.get("checks", [])[:15]:
        lines.append(
            f"[{str(check.get('outcome', 'info')).upper()}] {check.get('title', 'check')}: {check.get('summary', '')}"
        )
    return "\n".join(lines).strip()
