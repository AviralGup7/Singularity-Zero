"""Compliance Attestation Generator for SOC 2 and PCI DSS readiness.

Generates professional, auditor-grade HTML attestations from scan findings
and compliance mappings.
"""

from datetime import UTC, datetime
from typing import Any


def generate_compliance_attestation_html(
    target_name: str,
    run_id: str,
    compliance_report: dict[str, Any],
) -> str:
    """Generate a high-fidelity HTML attestation document.

    Args:
        target_name: Name of the security target.
        run_id: Unique identifier for the scan run.
        compliance_report: Data from build_compliance_report.

    Returns:
        HTML string for the attestation.
    """
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # CSS for "Cyber" Professional Look
    css = """
    :root {
        --primary: #00ff41;
        --bg: #ffffff;
        --text: #1a1a1a;
        --muted: #666666;
        --border: #dddddd;
        --fail: #dc2626;
        --at-risk: #f97316;
        --partial: #f59e0b;
        --pass: #10b981;
    }
    body {
        font-family: 'Inter', -apple-system, sans-serif;
        color: var(--text);
        background: var(--bg);
        line-height: 1.6;
        padding: 40px;
        max-width: 900px;
        margin: 0 auto;
    }
    .header {
        border-bottom: 2px solid var(--primary);
        padding-bottom: 20px;
        margin-bottom: 40px;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
    }
    .header h1 {
        margin: 0;
        font-size: 24px;
        letter-spacing: -0.02em;
        text-transform: uppercase;
    }
    .header .meta {
        text-align: right;
        font-size: 12px;
        color: var(--muted);
        font-family: monospace;
    }
    .section {
        margin-bottom: 40px;
    }
    .section h2 {
        font-size: 18px;
        border-left: 4px solid var(--primary);
        padding-left: 12px;
        margin-bottom: 20px;
    }
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 20px;
        margin-bottom: 30px;
    }
    .kpi-card {
        padding: 20px;
        border: 1px solid var(--border);
        border-radius: 8px;
    }
    .kpi-card label {
        display: block;
        font-size: 11px;
        text-transform: uppercase;
        color: var(--muted);
        margin-bottom: 8px;
    }
    .kpi-card value {
        display: block;
        font-size: 24px;
        font-weight: bold;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }
    th {
        text-align: left;
        background: #f8f9fa;
        padding: 12px;
        border-bottom: 2px solid var(--border);
    }
    td {
        padding: 12px;
        border-bottom: 1px solid var(--border);
        vertical-align: top;
    }
    .status-pill {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 10px;
        text-transform: uppercase;
    }
    .status-FAIL { background: rgba(220, 38, 38, 0.1); color: var(--fail); }
    .status-AT_RISK { background: rgba(249, 115, 22, 0.1); color: var(--at-risk); }
    .status-PARTIAL { background: rgba(245, 158, 11, 0.1); color: var(--partial); }
    .status-PASS { background: rgba(16, 185, 129, 0.1); color: var(--pass); }

    .finding-item {
        font-size: 11px;
        color: var(--muted);
        margin-top: 4px;
    }
    .footer {
        margin-top: 60px;
        padding-top: 20px;
        border-top: 1px solid var(--border);
        font-size: 11px;
        color: var(--muted);
        text-align: center;
    }
    @media print {
        body { padding: 0; }
        .no-print { display: none; }
    }
    """

    # Build Framework Content
    frameworks_html = ""
    for framework, controls in compliance_report.get("framework_coverage", {}).items():
        frameworks_html += f"""
        <div class="section">
            <h2>{framework}</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 120px;">Control ID</th>
                        <th>Status</th>
                        <th>Evidence / Findings</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
        """
        for cid, data in controls.items():
            findings_html = ""
            for f in data.get("findings", []):
                findings_html += f'<div class="finding-item">• {f["title"]} ({f["severity"]})</div>'
            
            if not findings_html:
                findings_html = '<div class="finding-item italic">No findings detected.</div>'

            frameworks_html += f"""
                    <tr>
                        <td><strong>{cid}</strong></td>
                        <td><span class="status-pill status-{data['maturity']}">{data['maturity']}</span></td>
                        <td>{findings_html}</td>
                        <td style="font-size: 11px;">{data['recommendation']}</td>
                    </tr>
            """
        frameworks_html += """
                </tbody>
            </table>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Compliance Attestation - {target_name}</title>
        <style>{css}</title>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>Compliance Attestation</h1>
                <div style="font-size: 14px; color: var(--muted);">Target: <strong>{target_name}</strong></div>
            </div>
            <div class="meta">
                ID: {run_id}<br>
                Generated: {generated_at}<br>
                Singularity-Zero Autonomous Engine
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="kpi-card">
                    <label>Total Findings</label>
                    <value>{compliance_report.get('total_findings', 0)}</value>
                </div>
                <div class="kpi-card">
                    <label>Frameworks Evaluated</label>
                    <value>{len(compliance_report.get('framework_coverage', {}))}</value>
                </div>
                <div class="kpi-card">
                    <label>Assessed At</label>
                    <value style="font-size: 14px;">{generated_at[:10]}</value>
                </div>
            </div>
            <p style="font-size: 13px; color: var(--muted);">
                This document provides an automated attestation of the security posture of <strong>{target_name}</strong> 
                against major regulatory frameworks. The assessments are derived from real-time autonomous security scans 
                performed by the Singularity-Zero engine.
            </p>
        </div>

        {frameworks_html}

        <div class="footer">
            Confidential - Authorized Access Only - Generated by Singularity-Zero Security Orchestration Pipeline
        </div>
        
        <div class="no-print" style="position: fixed; bottom: 20px; right: 20px;">
            <button onclick="window.print()" style="background: var(--primary); color: #000; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                Print to PDF
            </button>
        </div>
    </body>
    </html>
    """
    return html
