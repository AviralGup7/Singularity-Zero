"""Severity scores and MITRE ATT&CK mappings for findings."""

__all__ = [
    "SEVERITY_SCORES",
    "MITRE_ATTACK_MAPPING",
]

SEVERITY_SCORES = {
    "critical": 100,
    "high": 80,
    "medium": 55,
    "low": 30,
    "info": 15,
}

# MITRE ATT&CK technique mapping for security finding categories
# Maps pipeline detection categories to ATT&CK technique IDs and names
MITRE_ATTACK_MAPPING: dict[str, list[dict[str, str]]] = {
    "idor": [
        {
            "technique_id": "T1078.001",
            "name": "Valid Accounts: Default Accounts",
            "tactic": "Defense Evasion",
        }
    ],
    "access_control": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}
    ],
    "authentication_bypass": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {
            "technique_id": "T1550",
            "name": "Use Alternate Authentication Material",
            "tactic": "Defense Evasion",
        },
    ],
    "broken_authentication": [
        {"technique_id": "T1550.004", "name": "Web Session Cookie", "tactic": "Defense Evasion"}
    ],
    "token_leak": [
        {
            "technique_id": "T1550.001",
            "name": "Application Access Token",
            "tactic": "Defense Evasion",
        },
        {
            "technique_id": "T1539",
            "name": "Steal Web Session Cookie",
            "tactic": "Credential Access",
        },
    ],
    "ssrf": [
        {
            "technique_id": "T1210",
            "name": "Exploitation of Remote Services",
            "tactic": "Lateral Movement",
        }
    ],
    "xss": [{"technique_id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}],
    "open_redirect": [
        {"technique_id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"}
    ],
    "business_logic": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation"}
    ],
    "payment": [{"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access"}],
    "sensitive_data": [
        {"technique_id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"},
        {"technique_id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "exposure": [
        {
            "technique_id": "T1592",
            "name": "Gather Victim Host Information",
            "tactic": "Reconnaissance",
        }
    ],
    "misconfiguration": [
        {
            "technique_id": "T1592",
            "name": "Gather Victim Host Information",
            "tactic": "Reconnaissance",
        }
    ],
    "cors": [{"technique_id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"}],
    "redirect": [
        {"technique_id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"}
    ],
    "session": [
        {"technique_id": "T1550.004", "name": "Web Session Cookie", "tactic": "Defense Evasion"}
    ],
    "anomaly": [
        {
            "technique_id": "T1592",
            "name": "Gather Victim Host Information",
            "tactic": "Reconnaissance",
        }
    ],
    "behavioral_deviation": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation"}
    ],
    "race_condition": [
        {"technique_id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"}
    ],
    "server_side_injection": [
        {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
        }
    ],
}
