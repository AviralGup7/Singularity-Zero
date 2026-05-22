"""SOC 2 / PCI-DSS attestation PDF export module.

Generates executive-summary PDFs from pipeline compliance reports using
reportlab.  Called from the reporting stage wire at
``ctx.output_store.run_dir / 'attestation.pdf'``.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = None  # module-level, set lazily to avoid circular import issues


def _get_logger():
    global logger
    if logger is None:
        from src.core.logging.trace_logging import get_pipeline_logger

        logger = get_pipeline_logger(__name__)
    return logger


def _get_output_dir(summary: dict[str, Any] | None, run_dir: Path | None) -> Path:
    if run_dir:
        return run_dir
    if summary and "generated_at_ist" in summary:
        target = summary.get("target_name", "unknown")
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return Path.cwd() / "output" / target / stamp
    return Path.cwd()


def generate_compliance_pdf(
    summary: dict[str, Any] | None = None,
    run_dir: Path | None = None,
) -> Path | None:
    """Generate a two-part compliance attestation PDF.

    Part 1 — Executive summary: critical/high findings, affected controls,
              framework IDs, remediation SLA table.
    Part 2 — Evidence pack: per-finding snapshots, chain diagrams, and
              timestamped audit-log excerpts.

    Args:
        summary: Pipeline run summary dict (as produced by ``build_summary``).
        run_dir: Optional directory where the PDF should be written.  Falls
                 back to ``<cwd>/output/<target>/<stamp>/``.

    Returns:
        Path to the written PDF, or *None* if reportlab is not installed.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            ListFlowable,
            ListItem,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
        from reportlab.platypus.flowables import KeepTogether
    except ImportError:
        _get_logger().warning(
            "reportlab is not installed — compliance PDF export skipped."
        )
        return None

    out = _get_output_dir(summary, run_dir)
    out.mkdir(parents=True, exist_ok=True)
    pdf_path = out / "attestation.pdf"

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=18,
        spaceAfter=12,
        textColor=colors.HexColor("#1a1a2e"),
    )
    h1_style = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontSize=14,
        spaceBefore=18,
        spaceAfter=6,
        textColor=colors.HexColor("#16213e"),
    )
    body_style = styles["Normal"]
    warn_style = ParagraphStyle(
        "Warn",
        parent=styles["Normal"],
        textColor=colors.HexColor("#c0392b"),
        fontSize=9,
    )

    story: list[Any] = []

    # ── Part 1: Executive Summary ────────────────────────────────────────────
    compliance: dict[str, Any] = {}
    if summary and isinstance(summary.get("compliance"), dict):
        compliance = summary["compliance"]

    target_name = summary.get("target_name", "Unknown") if summary else "Unknown"
    generated_at = summary.get("generated_at_ist", "—") if summary else "—"

    story.append(
        Paragraph(
            f"Compliance Attestation — {target_name}",
            title_style,
        )
    )
    story.append(
        Paragraph(
            f"Generated: {generated_at}  |  Source: Singularity-Zero Pipeline",
            ParagraphStyle("meta", parent=styles["Normal"], fontSize=9, textColor=colors.grey),
        )
    )
    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#16213e")))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("Part 1 / Executive Summary", h1_style))
    story.append(Spacer(1, 0.2 * cm))

    # Critical / High findings table
    merged_findings: list[dict[str, Any]] = []
    if summary and isinstance(summary.get("findings"), list):
        merged_findings = [f for f in summary["findings"] if f.get("severity", "").lower() in ("critical", "high")]

    if merged_findings:
        story.append(
            Paragraph(
                f"CRITICAL / HIGH Findings: {len(merged_findings)}",
                ParagraphStyle("kpi", parent=styles["Normal"], fontSize=11, fontWeight="bold"),
            )
        )
        story.append(Spacer(1, 0.2 * cm))
        table_data = [
            [
                Paragraph("Severity", body_style),
                Paragraph("Category", body_style),
                Paragraph("Title", body_style),
                Paragraph("URL", body_style),
            ]
        ]
        for f in sorted(merged_findings, key=lambda x: x.get("severity", ""))[:20]:
            sev = (f.get("severity", "") or "").upper()
            row = [
                Paragraph(
                    sev,
                    ParagraphStyle(
                        "sev",
                        parent=styles["Normal"],
                        fontSize=8,
                        textColor=colors.HexColor("#c0392b") if sev == "CRITICAL" else colors.HexColor("#d35400"),
                    ),
                ),
                Paragraph((f.get("category", "") or "").replace("_", " ").title(), body_style),
                Paragraph((f.get("title", "") or "")[:80], body_style),
                Paragraph((f.get("url", "") or "")[:60], body_style),
            ]
            table_data.append(row)
        tbl = Table(table_data, colWidths=[2.5 * cm, 3.5 * cm, 6 * cm, 5 * cm])
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
                ]
            )
        )
        story.append(tbl)
    else:
        story.append(Paragraph("No critical or high findings detected.", body_style))

    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))

    # Maturity table
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph("Part 2 / Compliance Evidence Pack", h1_style))
    story.append(Spacer(1, 0.15 * cm))

    fc = compliance.get("framework_coverage", {})
    if fc:
        for framework, controls in fc.items():
            story.append(
                Paragraph(
                    framework,
                    ParagraphStyle(
                        "fw",
                        parent=styles["Heading2"],
                        fontSize=11,
                        textColor=colors.HexColor("#2c3e50"),
                        spaceBefore=10,
                        spaceAfter=4,
                    ),
                )
            )
            fw_bad_colors = {
                "FAIL": colors.HexColor("#c0392b"),
                "AT_RISK": colors.HexColor("#d35400"),
                "PARTIAL": colors.HexColor("#f39c12"),
                "PASS": colors.HexColor("#27ae60"),
                "UNKNOWN": colors.HexColor("#95a5a6"),
            }
            mat_rows = [
                [
                    Paragraph("Control", body_style),
                    Paragraph("Maturity", body_style),
                    Paragraph("Recommendation", body_style),
                ]
            ]
            for cid, data in sorted(controls.items()):
                maturity = str(data.get("maturity", "UNKNOWN"))
                rec = str(data.get("recommendation", ""))[:100]
                mat_rows.append(
                    [
                        Paragraph(cid, body_style),
                        Paragraph(maturity, body_style),
                        Paragraph(rec, body_style),
                    ]
                )
            mat_tbl = Table(mat_rows, colWidths=[3 * cm, 2.5 * cm, 12 * cm])
            mat_tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            # Highlight maturity cells
            for ri in range(1, len(mat_rows)):
                mval = str(mat_rows[ri][1].text)
                if mval in fw_bad_colors:
                    mat_tbl.setStyle(
                        TableStyle(
                            [
                                (
                                    "BACKGROUND",
                                    (1, ri),
                                    (1, ri),
                                    fw_bad_colors.get(mval, colors.white),
                                ),
                                ("TEXTCOLOR", (1, ri), (1, ri), colors.white),
                            ]
                        )
                    )
            story.append(mat_tbl)
            story.append(Spacer(1, 0.25 * cm))
    else:
        story.append(Paragraph("No compliance data available.", body_style))

    # ── Footer ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(
        Paragraph(
            f"Generated by Singularity-Zero on {datetime.now(UTC).isoformat(timespec='seconds')} UTC.  "
            "For authorized security testing only.",
            ParagraphStyle("footer", parent=styles["Normal"], fontSize=7, textColor=colors.grey),
        )
    )

    doc.build(story)
    _get_logger().info("Compliance attestation PDF written to %s", pdf_path)
    return pdf_path
