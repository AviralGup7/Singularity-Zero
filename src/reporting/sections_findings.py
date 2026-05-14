import html
from typing import Any

from src.execution.validators.api_test_integration import build_api_test_result

# MITRE ATT&CK technique display names for reporting
MITRE_TECHNIQUE_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1110": "Brute Force",
    "T1133": "External Remote Services",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1114": "Email Collection",
    "T1530": "Data from Cloud Storage",
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1074": "Data Staged",
    "T1565": "Data Manipulation",
    "T1499": "Endpoint Denial of Service",
    "T1498": "Network Denial of Service",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1134": "Access Token Manipulation",
    "T1136": "Create Account",
    "T1087": "Account Discovery",
    "T1069": "Permission Groups Discovery",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1046": "Network Service Discovery",
    "T1040": "Network Sniffing",
    "T1056": "Input Capture",
    "T1105": "Ingress Tool Transfer",
    "T1071": "Application Layer Protocol",
    "T1573": "Encrypted Channel",
    "T1572": "Protocol Tunneling",
    "T1571": "Non-Standard Port",
    "T1090": "Proxy",
    "T1092": "Communication Through Removable Media",
    "T1102": "Web Service",
    "T1568": "Dynamic Resolution",
    "T1560": "Archive Collected Data",
    "T1564": "Hide Artifacts",
    "T1562": "Impair Defenses",
    "T1561": "Disk Wipe",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1491": "Defacement",
    "T1529": "System Shutdown/Reboot",
    "T1531": "Account Access Removal",
    "T1542": "Pre-OS Boot",
    "T1543": "Create or Modify System Process",
    "T1546": "Event Triggered Execution",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1550": "Use Alternate Authentication Material",
    "T1552": "Unsecured Credentials",
    "T1553": "Subvert Trust Controls",
    "T1554": "Compromise Client Software Binary",
    "T1555": "Credentials from Password Stores",
    "T1556": "Modify Authentication Process",
    "T1557": "Adversary-in-the-Middle",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1559": "Inter-Process Communication",
    "T1563": "Remote Service Session Hijacking",
    "T1566": "Phishing",
    "T1569": "System Services",
    "T1570": "Lateral Tool Transfer",
    "T1574": "Hijack Execution Flow",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1580": "Cloud Infrastructure Discovery",
    "T1583": "Acquire Infrastructure",
    "T1584": "Compromise Infrastructure",
    "T1585": "Establish Accounts",
    "T1586": "Compromise Accounts",
    "T1587": "Develop Capabilities",
    "T1588": "Obtain Capabilities",
    "T1589": "Gather Victim Identity Information",
    "T1590": "Gather Victim Network Information",
    "T1591": "Gather Victim Org Information",
    "T1592": "Gather Victim Host Information",
    "T1593": "Search Open Websites/Domains",
    "T1594": "Search Victim-Owned Websites",
    "T1595": "Active Scanning",
    "T1596": "Search Open Technical Databases",
    "T1597": "Search Closed Sources",
    "T1598": "Phishing for Information",
    "T1599": "Network Boundary Bridging",
    "T1600": "Weaken Encryption",
    "T1601": "Modify System Image",
    "T1602": "Data from Configuration Repository",
    "T1606": "Forge Web Credentials",
    "T1607": "File Deletion",
    "T1608": "Stage Capabilities",
    "T1609": "Container Administration Command",
    "T1610": "Deploy Container",
    "T1611": "Escape to Host",
    "T1612": "Build Image on Host",
    "T1613": "Container and Resource Discovery",
    "T1614": "System Location Discovery",
    "T1615": "Group Policy Discovery",
    "T1619": "Cloud Storage Object Discovery",
    "T1620": "Reflective Code Loading",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1622": "Debugger Evasion",
    "T1623": "System Checks",
    "T1624": "Exploitation for Credential Access",
    "T1625": "Exploitation for Privilege Escalation",
    "T1626": "Exploitation for Defense Evasion",
    "T1627": "Exploitation for Discovery",
    "T1628": "Exploitation for Lateral Movement",
    "T1629": "Exploitation for Collection",
    "T1630": "Exploitation for Command and Control",
    "T1631": "Exploitation for Exfiltration",
    "T1632": "Exploitation for Impact",
    "T1633": "Exploitation for Reconnaissance",
    "T1634": "Exploitation for Resource Development",
    "T1635": "Exploitation for Initial Access",
    "T1636": "Exploitation for Persistence",
    "T1637": "Exploitation for Credential Access",
    "T1638": "Exploitation for Privilege Escalation",
    "T1639": "Exploitation for Defense Evasion",
    "T1640": "Exploitation for Discovery",
    "T1641": "Exploitation for Lateral Movement",
    "T1642": "Exploitation for Collection",
    "T1643": "Exploitation for Command and Control",
    "T1644": "Exploitation for Exfiltration",
    "T1645": "Exploitation for Impact",
    "T1646": "Exploitation for Reconnaissance",
    "T1647": "Exploitation for Resource Development",
    "T1648": "Exploitation for Initial Access",
    "T1649": "Exploitation for Persistence",
}


def _render_mitre_badges(mitre_techniques: list[dict[str, Any]]) -> str:
    """Render MITRE ATT&CK technique badges for a finding."""
    if not mitre_techniques:
        return ""
    badges = []
    for tech in mitre_techniques[:3]:  # Limit to 3 techniques per finding
        technique_id = tech.get("technique_id", "")
        technique_name = MITRE_TECHNIQUE_NAMES.get(technique_id, tech.get("technique_name", ""))
        tactic = tech.get("tactic", "")
        display_name = f"{technique_id}: {technique_name}" if technique_name else technique_id
        title_attr = f" title='{html.escape(tactic).replace(chr(39), '&#x27;')}'" if tactic else ""
        badges.append(f"<span class='mitre-badge'{title_attr}>{html.escape(display_name)}</span>")
    return f"<div class='mitre-techniques'>{''.join(badges)}</div>" if badges else ""


def _render_correlation_badge(item: dict[str, Any]) -> str:
    """Render correlation/attack chain badge if the finding is part of a multi-vector attack."""
    attack_chains = item.get("attack_chains", [])
    if not attack_chains:
        return ""
    chain_labels = []
    for chain in attack_chains[:2]:  # Limit to 2 chains
        readable = chain.replace("_", " ").title()
        chain_labels.append(f"<span class='chain-badge'>{html.escape(readable)}</span>")
    return f"<div class='attack-chains'>{''.join(chain_labels)}</div>"


def _observed_result_grid(item: dict[str, Any]) -> str:
    result = build_api_test_result(item)
    metric_specs = [
        ("Baseline", result.get("baseline_url", "") or "n/a"),
        ("Variant URL", result.get("variant_url", "") or "n/a"),
        ("Mutation", f"{result.get('parameter', 'n/a')}={result.get('variant', 'n/a')}"),
    ]

    summary_map: dict[str, str] = {}
    for line in str(result.get("summary", "")).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        summary_map[key.strip()] = value.strip()

    metric_specs.extend(
        [
            ("Method", summary_map.get("Observed Method", "n/a")),
            ("Status Changed", summary_map.get("Status Changed", "unknown")),
            ("Content Changed", summary_map.get("Content Changed", "unknown")),
            ("Redirect Changed", summary_map.get("Redirect Changed", "unknown")),
            ("Body Similarity", summary_map.get("Body Similarity", "n/a")),
            ("Length Delta", summary_map.get("Length Delta", "n/a")),
            ("Shared Fields", summary_map.get("Shared Key Fields", "none")),
            ("Replay ID", summary_map.get("Replay ID", "n/a")),
        ]
    )

    cells = "".join(
        "<div class='finding-metric'>"
        f"<strong>{html.escape(label)}</strong>{html.escape(value)}"
        "</div>"
        for label, value in metric_specs
    )
    return f"<div class='finding-grid'>{cells}</div>"


def _review_summary_grid(item: dict[str, Any]) -> str:
    metric_specs = [
        ("Type", str(item.get("category", "review")).replace("_", " ")),
        ("Endpoint", str(item.get("endpoint_type", "GENERAL"))),
        ("Confidence", f"{round(float(item.get('confidence', 0)) * 100)}%"),
        ("Status", str(item.get("history_status", "new"))),
    ]
    if item.get("combined_signal"):
        metric_specs.append(("Signal", str(item.get("combined_signal", "none"))))
    cells = "".join(
        "<div class='finding-metric'>"
        f"<strong>{html.escape(label)}</strong>{html.escape(value)}"
        "</div>"
        for label, value in metric_specs
    )
    return f"<div class='finding-grid'>{cells}</div>"


def _render_cvss_badge(item: dict[str, Any]) -> str:
    """Render CVSS score badge if available."""
    cvss = item.get("cvss")
    if not cvss:
        return ""
    base_score = cvss.get("base_score", 0)
    vector = cvss.get("vector_string", "")
    severity = cvss.get("severity", "").upper()
    color = {
        "NONE": "#959595",
        "LOW": "#33cc33",
        "MEDIUM": "#ffcc00",
        "HIGH": "#ff6600",
        "CRITICAL": "#cc0000",
    }.get(severity, "#959595")
    return f"<span class='cvss-badge' style='background:{color};color:#fff;padding:2px 6px;border-radius:3px;font-size:0.85em;' title='{html.escape(vector).replace(chr(39), '&#x27;')}'>CVSS {base_score:.1f} ({severity})</span> "


def _render_attack_chain_badge(item: dict[str, Any]) -> str:
    """Render attack chain badge if finding is part of a chain."""
    evidence = item.get("evidence", {}) or {}
    chain = evidence.get("attack_chain")
    if not chain:
        return ""
    return f"<span class='chain-badge' style='background:#9b59b6;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.85em;' title='Part of attack chain'>⛓️ {html.escape(chain).replace(chr(39), '&#x27;')}</span> "


def top_findings_section(summary: dict[str, Any]) -> str:
    items = summary.get("top_actionable_findings", [])
    if not items:
        return "<section><h2>Top Actionable Findings</h2><p class='muted'>No prioritized findings yet.</p></section>"
    rows = []
    seen_endpoints: set[str] = set()
    for item in items:
        endpoint_key = str(item.get("evidence", {}).get("endpoint_key") or item.get("url", ""))
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        # Build explanation from score_breakdown if available
        explanation_parts = []
        score_breakdown = item.get("score_breakdown")
        if isinstance(score_breakdown, dict):
            for key, value in score_breakdown.items():
                if isinstance(value, (int, float)) and value > 0:
                    readable_key = key.replace("_", " ").title()
                    explanation_parts.append(f"{readable_key}: {value}")
        explanation_text = item.get("explanation", "")
        if explanation_parts:
            explanation_text = ("; ".join(explanation_parts) + ". " + explanation_text).strip()
        rows.append(
            "<li>"
            f"<strong>{html.escape(str(item.get('severity', 'info')).upper())}</strong> "
            f"{html.escape(item.get('title', 'Finding'))} "
            f"{_render_cvss_badge(item)}"
            f"{_render_attack_chain_badge(item)}"
            f"<span class='muted'>score {html.escape(str(item.get('score', 0)))} | confidence {html.escape(str(round(float(item.get('confidence', 0)) * 100)))}% | {html.escape(str(item.get('history_status', 'new')))}</span><br>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>{html.escape(explanation_text)}</span>"
            f"{_render_mitre_badges(item.get('mitre_attack', []))}"
            f"{_render_correlation_badge(item)}"
            "</li>"
        )
        if len(rows) >= 5:
            break
    return f"<section><h2>Top Actionable Findings</h2><ul>{''.join(rows)}</ul></section>"


def high_confidence_shortlist_section(summary: dict[str, Any]) -> str:
    items = summary.get("high_confidence_shortlist", [])
    if not items:
        return "<section><h2>High-Confidence Shortlist</h2><p class='muted'>No shortlist entries yet.</p></section>"
    rows = [
        "<li>"
        f"<strong>{html.escape(str(item.get('severity', 'info')).upper())}</strong> "
        f"{html.escape(item.get('title', 'Shortlist item'))} "
        f"<span class='muted'>{html.escape(str(item.get('category', 'unknown')))} | confidence {html.escape(str(round(float(item.get('confidence', 0)) * 100)))}% | {html.escape(str(item.get('history_status', 'new')))}</span><br>"
        f"{html.escape(item.get('url', ''))}<br>"
        f"<span class='muted'>{html.escape(item.get('explanation', item.get('next_step', '')))}</span>"
        "</li>"
        for item in items[:5]
    ]
    return f"<section><h2>High-Confidence Shortlist</h2><ul>{''.join(rows)}</ul></section>"


def manual_verification_section(summary: dict[str, Any]) -> str:
    items = summary.get("manual_verification_queue", [])
    if not items:
        return "<section><h2>Manual Verification Queue</h2><p class='muted'>No queued review tasks.</p></section>"
    rows = []
    for item in items:
        review_brief = html.escape(item.get("review_brief", ""), quote=True)
        review_url = html.escape(item.get("url", ""), quote=True)
        replay_url = html.escape(item.get("replay_url", ""), quote=True)
        anonymous_replay_url = html.escape(item.get("anonymous_replay_url", ""), quote=True)
        poc_curl = html.escape(item.get("poc_curl", ""), quote=True)
        poc_python = html.escape(item.get("poc_python", ""), quote=True)
        chain_summary = html.escape(item.get("chain_summary", ""), quote=True)
        is_api_replay_candidate = bool(item.get("is_api_replay_candidate"))
        sq = chr(39)
        replay_button = (
            f"<button type='button' class='action-btn replay-variant' data-replay-url='{replay_url.replace(sq, '&#x27;')}'>Replay API Variant</button>"
            if replay_url and is_api_replay_candidate
            else ""
        )
        anonymous_replay_button = (
            f"<button type='button' class='action-btn replay-variant' data-replay-url='{anonymous_replay_url.replace(sq, '&#x27;')}'>Replay As Anonymous</button>"
            if anonymous_replay_url and is_api_replay_candidate
            else ""
        )
        curl_button = (
            f"<button type='button' class='action-btn copy-proof-script' data-proof-script='{poc_curl.replace(sq, '&#x27;')}' data-default-label='Copy curl PoC'>Copy curl PoC</button>"
            if poc_curl
            else ""
        )
        python_button = (
            f"<button type='button' class='action-btn copy-proof-script' data-proof-script='{poc_python.replace(sq, '&#x27;')}' data-default-label='Copy Python PoC'>Copy Python PoC</button>"
            if poc_python
            else ""
        )
        detail_block = (
            _observed_result_grid(item) if is_api_replay_candidate else _review_summary_grid(item)
        )
        section_hint = (
            "<span class='muted'>Observed API replay result</span>"
            if is_api_replay_candidate
            else "<span class='muted'>Manual review summary</span>"
        )
        tone = (
            "bad"
            if str(item.get("severity", "")).lower() == "high"
            else "warn"
            if str(item.get("severity", "")).lower() == "medium"
            else "ok"
        )
        chain_meta = (
            f"<div class='meta'>Chain simulation: {chain_summary}</div>" if chain_summary else ""
        )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(str(item.get('severity', 'info')))}</span>"
            f"<strong>{html.escape(item.get('title', 'Review finding'))}</strong> "
            f"<span class='muted'>confidence {html.escape(str(round(float(item.get('confidence', 0)) * 100)))}% | {html.escape(str(item.get('history_status', 'new')))}</span>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>{html.escape(item.get('explanation', item.get('next_step', '')))}</span>"
            f"{chain_meta}"
            f"<div class='meta'>{section_hint}</div>"
            f"{detail_block}"
            "<div class='action-row'>"
            f"<button type='button' class='action-btn copy-review-brief' data-review-brief='{review_brief.replace(chr(39), '&#x27;')}'>Copy Review Note</button>"
            f"<button type='button' class='action-btn open-review-url' data-review-url='{review_url.replace(chr(39), '&#x27;')}'>Open URL</button>"
            f"{replay_button}"
            f"{anonymous_replay_button}"
            f"{curl_button}"
            f"{python_button}"
            "</div>"
            "</li>"
        )
    return f"<section><h2>Manual Verification Queue</h2><ul>{''.join(rows)}</ul></section>"


def verified_exploits_section(summary: dict[str, Any]) -> str:
    items = summary.get("verified_exploits", [])
    if not items:
        return "<section><h2>Validated Leads</h2><p class='muted'>No evidence-backed leads were promoted by the built-in validation runtime for this run.</p></section>"
    rows = []
    for item in items:
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge bad'>{html.escape(str(item.get('severity', 'info')).upper())}</span>"
            f"<strong>{html.escape(item.get('title', 'Verified result'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}"
            f"{_observed_result_grid(item)}"
            "<div class='action-row'>"
            f"<button type='button' class='action-btn open-review-url' data-review-url='{html.escape(item.get('url', ''), quote=True)}'>Open URL</button>"
            "</div>"
            "</li>"
        )
    return f"<section><h2>Validated Leads</h2><ul>{''.join(rows)}</ul></section>"


def signal_quality_section(summary: dict[str, Any]) -> str:
    findings = summary.get("top_actionable_findings", [])
    likely_true_positives = sum(
        1
        for item in findings
        if float(item.get("confidence", 0)) >= 0.8
        and item.get("endpoint_type") not in {"AUTH", "STATIC"}
    )
    likely_noise = sum(
        1
        for item in findings
        if item.get("endpoint_type") in {"AUTH", "STATIC"}
        or float(item.get("confidence", 0)) < 0.65
    )
    multi_signal = sum(1 for item in findings if item.get("combined_signal"))
    rows = (
        f"<div class='card'><div class='label'>Likely True Positives</div><div class='value'>{likely_true_positives}</div></div>"
        f"<div class='card'><div class='label'>Likely Noise</div><div class='value'>{likely_noise}</div></div>"
        f"<div class='card'><div class='label'>Multi-Signal Flows</div><div class='value'>{multi_signal}</div></div>"
    )
    return f"<section><h2>Signal Quality</h2><div class='grid'>{rows}</div></section>"


def auth_bypass_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("auth_bypass_check", [])
    if not items:
        return "<section><h2>Auth Bypass Findings</h2><p class='muted'>No authentication bypass indicators detected.</p></section>"
    rows = []
    for item in items[:20]:
        category = str(item.get("category", "auth_bypass")).replace("_", " ")
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        probe_type = evidence.get("probe_type", "unknown")
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'Auth bypass finding'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>category: {html.escape(category)} | probe: {html.escape(probe_type)} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span>"
            f"{_render_mitre_badge_for_auth_bypass(item)}"
            "</li>"
        )
    return (
        f"<section><h2>Auth Bypass Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"
    )


def _render_mitre_badge_for_auth_bypass(item: dict[str, Any]) -> str:
    mitre_techniques = item.get("mitre_attack", [])
    if not mitre_techniques:
        default_techniques = [
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"},
            {
                "technique_id": "T1134",
                "technique_name": "Access Token Manipulation",
                "tactic": "Privilege Escalation",
            },
        ]
        return _render_mitre_badges(default_techniques)
    return _render_mitre_badges(mitre_techniques)


def access_control_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("access_control_analyzer", [])
    if not items:
        return "<section><h2>Access Control Findings</h2><p class='muted'>No authorization bypass indicators detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        evidence = item.get("evidence", {})
        test_context = evidence.get("test_context", "unknown")
        result = evidence.get("result", "unknown")
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'Access control finding'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>context: {html.escape(test_context)} | result: {html.escape(result)} | confidence: {confidence}%</span>"
            f"{_render_mitre_badge_for_access_control(item)}"
            "</li>"
        )
    return f"<section><h2>Access Control Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"


def _render_mitre_badge_for_access_control(item: dict[str, Any]) -> str:
    mitre_techniques = item.get("mitre_attack", [])
    if not mitre_techniques:
        default_techniques = [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"},
        ]
        return _render_mitre_badges(default_techniques)
    return _render_mitre_badges(mitre_techniques)


def jwt_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("jwt_security_analyzer", [])
    if not items:
        return "<section><h2>JWT Security Findings</h2><p class='muted'>No JWT vulnerabilities detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        token_preview = evidence.get("token_preview", "N/A")
        total_attacks = evidence.get("total_attacks", 0)
        vulnerable_attacks = evidence.get("vulnerable_attacks", 0)
        original_alg = evidence.get("original_algorithm", "unknown")
        attack_details = evidence.get("attack_details", [])
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        attack_type_badges = ""
        for detail in attack_details[:3]:
            finding_type = html.escape(detail.get("finding", ""))
            status_code = detail.get("status_code", "")
            attack_type_badges += (
                f"<span class='finding-badge' style='background:#e74c3c;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;margin-right:4px;' "
                f"title='Status: {status_code}'>{finding_type}</span> "
            )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'JWT vulnerability'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>algorithm: {html.escape(str(original_alg))} | token: {html.escape(str(token_preview))} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>attacks tested: {total_attacks} | vulnerable: {vulnerable_attacks}</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span><br>"
            f"<div style='margin-top:6px'>{attack_type_badges}</div>"
            f"{_render_mitre_badges([{'technique_id': 'T1078', 'technique_name': 'Valid Accounts', 'tactic': 'Initial Access'}, {'technique_id': 'T1134', 'technique_name': 'Access Token Manipulation', 'tactic': 'Privilege Escalation'}])}"
            "</li>"
        )
    return (
        f"<section><h2>JWT Security Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"
    )


def tenant_isolation_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("tenant_isolation_check", [])
    if not items:
        return "<section><h2>Tenant Isolation Findings</h2><p class='muted'>No tenant isolation vulnerabilities detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        probe_type = evidence.get("probe_type", evidence.get("test_type", "unknown"))
        tenant_params = evidence.get("tenant_parameters", {})
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        tenant_param_names = ""
        if isinstance(tenant_params, dict):
            tenant_param_names = ", ".join(tenant_params.get("tenant_params", [])[:5])
        elif isinstance(tenant_params, list):
            tenant_param_names = ", ".join(str(p) for p in tenant_params[:5])
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'Tenant isolation finding'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>category: tenant_isolation | probe: {html.escape(str(probe_type))} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>tenant params: {html.escape(tenant_param_names) or 'inferred'}</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span>"
            f"{_render_mitre_badges([{'technique_id': 'T1078', 'technique_name': 'Valid Accounts', 'tactic': 'Lateral Movement'}, {'technique_id': 'T1069', 'technique_name': 'Permission Groups Discovery', 'tactic': 'Privilege Escalation'}])}"
            "</li>"
        )
    return f"<section><h2>Tenant Isolation Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"


def graphql_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("graphql_introspection_check", [])
    if not items:
        return "<section><h2>GraphQL Introspection &amp; Schema Findings</h2><p class='muted'>No GraphQL vulnerabilities detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        type_count = evidence.get("type_count", "N/A")
        query_type = evidence.get("query_type", "N/A")
        mutation_type = evidence.get("mutation_type", "N/A")
        dangerous_mutations = evidence.get("dangerous_mutations", [])
        max_depth = evidence.get("max_successful_depth", "N/A")
        batch_size = evidence.get("batch_size_accepted", "N/A")
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        mutation_badges = ""
        for m in dangerous_mutations[:5]:
            mutation_badges += (
                f"<span class='finding-badge' style='background:#e74c3c;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;margin-right:4px;' "
                f"title='Dangerous mutation'>{html.escape(m)}</span> "
            )
        detail_parts = []
        if type_count != "N/A":
            detail_parts.append(f"types: {type_count}")
        if query_type != "N/A":
            detail_parts.append(f"query: {query_type}")
        if mutation_type != "N/A":
            detail_parts.append(f"mutation: {mutation_type}")
        if max_depth != "N/A":
            detail_parts.append(f"max depth: {max_depth}")
        if batch_size != "N/A":
            detail_parts.append(f"batch size: {batch_size}")
        detail_text = " | ".join(detail_parts)
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'GraphQL vulnerability'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>{html.escape(detail_text)} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span><br>"
            f"<div style='margin-top:6px'>{mutation_badges}</div>"
            f"{_render_mitre_badges([{'technique_id': 'T1046', 'technique_name': 'Network Service Discovery', 'tactic': 'Discovery'}, {'technique_id': 'T1499', 'technique_name': 'Endpoint Denial of Service', 'tactic': 'Impact'}])}"
            "</li>"
        )
    return f"<section><h2>GraphQL Introspection &amp; Schema Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"
