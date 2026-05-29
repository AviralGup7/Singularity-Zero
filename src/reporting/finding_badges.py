"""HTML badges rendering helpers for findings report."""

from __future__ import annotations

import html
from typing import Any

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


def render_mitre_badges(mitre_techniques: list[dict[str, Any]]) -> str:
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


def render_mitre_badge_for_auth_bypass(item: dict[str, Any]) -> str:
    """Render MITRE badges specifically tailored for Auth Bypass."""
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
        return render_mitre_badges(default_techniques)
    return render_mitre_badges(mitre_techniques)


def render_mitre_badge_for_access_control(item: dict[str, Any]) -> str:
    """Render MITRE badges specifically tailored for Access Control."""
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
        return render_mitre_badges(default_techniques)
    return render_mitre_badges(mitre_techniques)


def render_correlation_badge(item: dict[str, Any]) -> str:
    """Render correlation/attack chain badge if the finding is part of a multi-vector attack."""
    attack_chains = item.get("attack_chains", [])
    if not attack_chains:
        return ""
    chain_labels = []
    for chain in attack_chains[:2]:  # Limit to 2 chains
        readable = chain.replace("_", " ").title()
        chain_labels.append(f"<span class='chain-badge'>{html.escape(readable)}</span>")
    return f"<div class='attack-chains'>{''.join(chain_labels)}</div>"


def render_cvss_badge(item: dict[str, Any]) -> str:
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


def render_attack_chain_badge(item: dict[str, Any]) -> str:
    """Render attack chain badge if finding is part of a chain."""
    evidence = item.get("evidence", {}) or {}
    chain = evidence.get("attack_chain")
    if not chain:
        return ""
    return f"<span class='chain-badge' style='background:#9b59b6;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.85em;' title='Part of attack chain'>⛓️ {html.escape(chain).replace(chr(39), '&#x27;')}</span> "


def render_model_badge(item: dict[str, Any]) -> str:
    """Render calibrated ML severity metadata."""
    score = item.get("severity_score")
    model = item.get("severity_model") or {}
    signal = item.get("signal_quality") or {}
    signal_score = item.get("signal_quality_score", signal.get("quality_score"))
    if score is None and not model and signal_score is None:
        return ""
    tp = float(item.get("true_positive_probability", model.get("true_positive_probability", 0.0)))
    fp = float(item.get("false_positive_probability", model.get("false_positive_probability", 0.0)))
    title = (
        f"Calibrated ML severity. TP probability {tp:.1%}; "
        f"FP probability {fp:.1%}; samples {model.get('training_samples', 0)}"
    )
    signal_badge = ""
    if signal_score is not None:
        action = str(signal.get("action", "keep")).replace("_", " ")
        signal_title = f"Signal quality {float(signal_score):.1f}; action {action}; FP {fp:.1%}"
        signal_badge = (
            "<span class='model-badge' "
            "style='background:#14532d;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.85em;' "
            f"title='{html.escape(signal_title).replace(chr(39), '&#x27;')}'>"
            f"Signal {float(signal_score):.0f}</span> "
        )
    return (
        "<span class='model-badge' "
        "style='background:#164e63;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.85em;' "
        f"title='{html.escape(title).replace(chr(39), '&#x27;')}'>"
        f"ML {float(score or 0.0):.2f}</span> "
        f"{signal_badge}"
    )
