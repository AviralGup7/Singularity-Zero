"""Compliance-ready report artefact generation and verification."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from src.pipeline.storage import write_json
from src.reporting.compliance_attestation import generate_compliance_attestation_html

REPORT_SCHEMA_VERSION = "2026-05.compliance-report.v1"
CYCLONEDX_VERSION = "1.5"
DEFAULT_STANDARDS = [
    "OWASP Top 10 (2021)",
    "NIST SP 800-53 Rev. 5",
    "ISO/IEC 27001:2022 Annex A",
    "PCI DSS v4.0",
    "CycloneDX 1.5",
]
SIGNED_FILENAMES = [
    "report.html",
    "report.json",
    "sbom.cdx.json",
    "compliance_coverage.json",
    "compliance_maturity.json",
    "attestation.html",
    "attestation.pdf",
]


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _finding_id(target_name: str, run_id: str, index: int, finding: dict[str, Any]) -> str:
    raw = _safe_text(finding.get("id") or finding.get("finding_id"))
    if raw:
        return raw
    seed = canonical_json(
        {
            "target": target_name,
            "run": run_id,
            "index": index,
            "title": finding.get("title") or finding.get("type") or finding.get("category"),
            "url": finding.get("url"),
        }
    )
    return f"finding-{sha256_bytes(seed)[:12]}"


def build_structured_report(
    *,
    target_name: str,
    run_id: str,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    diff_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    normalized_findings = []
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue
        normalized_findings.append(
            {
                "id": _finding_id(target_name, run_id, index, finding),
                "title": _safe_text(
                    finding.get("title") or finding.get("type") or finding.get("category")
                ),
                "category": _safe_text(finding.get("category") or finding.get("type")),
                "severity": _safe_text(finding.get("severity") or "info").lower(),
                "confidence": finding.get("confidence"),
                "url": _safe_text(finding.get("url")),
                "status": _safe_text(finding.get("status") or "open").lower(),
                "evidence": finding.get("evidence", {}),
                "compliance": finding.get("compliance", {}),
            }
        )

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": target_name,
        "run_id": run_id,
        "generated_at": summary.get("generated_at_utc") or _now_iso(),
        "standards": DEFAULT_STANDARDS,
        "summary": {
            "counts": summary.get("counts", {}),
            "scan_quality": summary.get("scan_quality", {}),
            "duration_seconds": summary.get("duration_seconds", 0),
            "previous_run": summary.get("previous_run", ""),
        },
        "compliance": summary.get("compliance", {}),
        "diff": diff_summary or {},
        "findings": normalized_findings,
        "artefacts": {
            "html": "report.html",
            "json": "report.json",
            "sbom": "sbom.cdx.json",
            "attestation_html": "attestation.html",
            "attestation_pdf": "attestation.pdf",
            "manifest": "report_manifest.json",
            "signature": "report_manifest.sig",
        },
    }


def build_cyclonedx_sbom(
    *,
    target_name: str,
    run_id: str,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    tools = summary.get("tool_availability", {})
    components = [
        {
            "type": "application",
            "name": target_name,
            "version": run_id,
            "bom-ref": f"target:{target_name}:{run_id}",
            "properties": [
                {"name": "pipeline:reportable_findings", "value": str(len(findings))},
                {"name": "pipeline:standards", "value": ",".join(DEFAULT_STANDARDS)},
            ],
        }
    ]
    if isinstance(tools, dict):
        for name, available in sorted(tools.items()):
            components.append(
                {
                    "type": "application",
                    "name": str(name),
                    "version": "available" if available else "unavailable",
                    "bom-ref": f"tool:{name}",
                    "properties": [
                        {"name": "pipeline:tool_available", "value": str(bool(available)).lower()}
                    ],
                }
            )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "serialNumber": f"urn:uuid:{sha256_bytes(f'{target_name}:{run_id}'.encode())[:32]}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "component": {
                "type": "application",
                "name": "cyber-security-test-pipeline",
                "version": "2.0.0",
            },
            "properties": [
                {"name": "report:schema_version", "value": REPORT_SCHEMA_VERSION},
                {"name": "report:run_id", "value": run_id},
            ],
        },
        "components": components,
    }


def _load_or_create_private_key(key_dir: Path) -> Ed25519PrivateKey:
    env_key = os.getenv("REPORTING_ATTESTATION_PRIVATE_KEY_PEM")
    if env_key:
        loaded = load_pem_private_key(env_key.encode("utf-8"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("REPORTING_ATTESTATION_PRIVATE_KEY_PEM must be an Ed25519 PEM key")
        return loaded

    key_path = key_dir / ".attestation_ed25519.pem"
    if key_path.exists():
        loaded = load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"Unsupported attestation key type in {key_path}")
        return loaded

    private_key = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
    )
    try:
        os.chmod(key_path, 0o600)
    except Exception:  # noqa: S110
        pass
    return private_key


def _public_key_b64(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _previous_manifest_hash(run_dir: Path) -> str:
    target_root = run_dir.parent
    previous_runs = sorted(
        child
        for child in target_root.iterdir()
        if child.is_dir() and child != run_dir and (child / "report_manifest.json").exists()
    )
    if not previous_runs:
        return ""
    return sha256_file(previous_runs[-1] / "report_manifest.json")


def _pdf_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )


def _write_simple_pdf(path: Path, lines: list[str]) -> None:
    content_lines = ["BT", "/F1 12 Tf", "72 760 Td", "14 TL"]
    for line in lines[:44]:
        content_lines.append(f"({_pdf_escape(line[:100])}) Tj")
        content_lines.append("T*")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "
        + str(len(stream)).encode("ascii")
        + b" >>\nstream\n"
        + stream
        + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )
    path.write_bytes(bytes(output))


def _attestation_pdf_lines(target_name: str, run_id: str, report: dict[str, Any]) -> list[str]:
    compliance = report.get("compliance", {})
    lines = [
        "Compliance Attestation",
        f"Target: {target_name}",
        f"Run: {run_id}",
        f"Generated: {_now_iso()}",
        f"Standards: {', '.join(DEFAULT_STANDARDS)}",
        f"Total findings: {compliance.get('total_findings', 0)}",
        "",
        "Framework coverage:",
    ]
    for framework, controls in compliance.get("framework_coverage", {}).items():
        lines.append(f"- {framework}: {len(controls)} controls evaluated")
    lines.extend(
        [
            "",
            "Signature status: see report_manifest.json and report_manifest.sig.",
            "This PDF is generated from the signed report package.",
        ]
    )
    return lines


def write_report_package(
    *,
    run_dir: Path,
    target_name: str,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    diff_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write report JSON, SBOM, attestation, and signed manifest files."""
    run_id = run_dir.name
    run_dir.mkdir(parents=True, exist_ok=True)

    report = build_structured_report(
        target_name=target_name,
        run_id=run_id,
        summary=summary,
        findings=findings,
        diff_summary=diff_summary,
    )
    sbom = build_cyclonedx_sbom(
        target_name=target_name,
        run_id=run_id,
        summary=summary,
        findings=findings,
    )

    write_json(run_dir / "report.json", report)
    write_json(run_dir / "sbom.cdx.json", sbom)

    attestation_html = generate_compliance_attestation_html(
        target_name=target_name,
        run_id=run_id,
        compliance_report=summary.get("compliance", {}),
    )
    (run_dir / "attestation.html").write_text(attestation_html, encoding="utf-8")
    pdf_path = None
    try:
        from src.reporting.compliance_pdf import generate_compliance_pdf
        pdf_path = generate_compliance_pdf(summary=summary, run_dir=run_dir)
    except Exception:  # noqa: S110
        pass

    if pdf_path is None or not pdf_path.exists():
        _write_simple_pdf(
            run_dir / "attestation.pdf", _attestation_pdf_lines(target_name, run_id, report)
        )

    private_key = _load_or_create_private_key(run_dir.parent)
    public_key = private_key.public_key()
    artifacts = {}
    for filename in SIGNED_FILENAMES:
        path = run_dir / filename
        if path.exists():
            artifacts[filename] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }

    manifest_unsigned = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": target_name,
        "run_id": run_id,
        "generated_at": _now_iso(),
        "standards": DEFAULT_STANDARDS,
        "previous_manifest_sha256": _previous_manifest_hash(run_dir),
        "artifacts": artifacts,
        "signature": {
            "algorithm": "Ed25519",
            "public_key": _public_key_b64(public_key),
        },
    }
    payload = canonical_json(manifest_unsigned)
    signature = base64.b64encode(private_key.sign(payload)).decode("ascii")
    manifest = {
        **manifest_unsigned,
        "signature": {
            **cast(dict[str, Any], manifest_unsigned["signature"]),
            "value": signature,
            "signed_payload_sha256": sha256_bytes(payload),
        },
    }
    write_json(run_dir / "report_manifest.json", manifest)
    (run_dir / "report_manifest.sig").write_text(signature + "\n", encoding="ascii")
    return manifest


def verify_report_package(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "report_manifest.json"
    if not manifest_path.exists():
        return {"valid": False, "errors": ["report_manifest.json is missing"]}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = []

    for filename, meta in manifest.get("artifacts", {}).items():
        path = run_dir / filename
        if not path.exists():
            errors.append(f"{filename} is missing")
            continue
        expected = meta.get("sha256")
        actual = sha256_file(path)
        if expected != actual:
            errors.append(f"{filename} sha256 mismatch")

    signature_meta = dict(manifest.get("signature", {}))
    signature_value = signature_meta.pop("value", "")
    signature_meta.pop("signed_payload_sha256", None)
    unsigned = {**manifest, "signature": signature_meta}
    payload = canonical_json(unsigned)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(signature_meta.get("public_key", ""))
        )
        public_key.verify(base64.b64decode(signature_value), payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        errors.append(f"manifest signature invalid: {exc}")

    return {
        "valid": not errors,
        "errors": errors,
        "manifest_sha256": sha256_file(manifest_path),
        "target": manifest.get("target", ""),
        "run_id": manifest.get("run_id", ""),
    }


def report_links_for_run(target_name: str, run_id: str) -> dict[str, str]:
    base = f"/reports/{target_name}/{run_id}"
    return {
        "html": f"{base}/report.html",
        "json": f"{base}/report.json",
        "sbom": f"{base}/sbom.cdx.json",
        "attestation_html": f"{base}/attestation.html",
        "attestation_pdf": f"{base}/attestation.pdf",
        "manifest": f"{base}/report_manifest.json",
        "signature": f"{base}/report_manifest.sig",
    }


def build_report_library(output_root: Path) -> dict[str, Any]:
    reports: list[dict[str, Any]] = []
    if not output_root.exists():
        return {"reports": reports, "total": 0}
    for target_dir in sorted(output_root.iterdir(), key=lambda item: item.name.lower()):
        if not target_dir.is_dir() or target_dir.name.startswith("_"):
            continue
        for run_dir in sorted(target_dir.iterdir(), key=lambda item: item.name, reverse=True):
            summary_path = run_dir / "run_summary.json"
            if not run_dir.is_dir() or not summary_path.exists():
                continue
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                summary = {}
            manifest_path = run_dir / "report_manifest.json"
            manifest = {}
            verification = {"valid": False, "errors": ["report manifest is missing"]}
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    verification = verify_report_package(run_dir)
                except (json.JSONDecodeError, OSError, ValueError) as exc:
                    verification = {"valid": False, "errors": [str(exc)]}
            reports.append(
                {
                    "target": target_dir.name,
                    "run_id": run_dir.name,
                    "generated_at": summary.get("generated_at_utc")
                    or summary.get("generated_at_ist")
                    or manifest.get("generated_at")
                    or run_dir.name,
                    "finding_count": int(
                        summary.get("counts", {}).get("validation_results")
                        or summary.get("counts", {}).get("findings")
                        or summary.get("compliance", {}).get("total_findings", 0)
                    ),
                    "standards": manifest.get("standards", DEFAULT_STANDARDS),
                    "manifest_sha256": verification.get("manifest_sha256", ""),
                    "signature_valid": bool(verification.get("valid")),
                    "signature_errors": verification.get("errors", []),
                    "version": manifest.get("schema_version", REPORT_SCHEMA_VERSION),
                    "previous_manifest_sha256": manifest.get("previous_manifest_sha256", ""),
                    "links": report_links_for_run(target_dir.name, run_dir.name),
                }
            )
    return {"reports": reports, "total": len(reports)}


def report_library_index_html(target_root: Path, reports: list[dict[str, Any]]) -> str:
    rows = []
    for report in reports:
        links = report.get("links", {})
        valid_label = "valid" if report.get("signature_valid") else "needs review"
        rows.append(
            "<tr>"
            f"<td>{html.escape(_safe_text(report.get('run_id')))}</td>"
            f"<td>{html.escape(_safe_text(report.get('generated_at')))}</td>"
            f"<td>{html.escape(_safe_text(report.get('version')))}</td>"
            f"<td>{html.escape(valid_label)}</td>"
            f"<td><a href='{html.escape(links.get('html', '#'))}'>HTML</a> "
            f"<a href='{html.escape(links.get('attestation_pdf', '#'))}'>PDF</a> "
            f"<a href='{html.escape(links.get('manifest', '#'))}'>Manifest</a></td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td colspan='5'>No signed reports yet.</td></tr>"
    return (
        "<section><h2>Signed Report Versions</h2>"
        "<table><thead><tr><th>Run</th><th>Generated</th><th>Schema</th>"
        "<th>Signature</th><th>Artefacts</th></tr></thead>"
        f"<tbody>{body}</tbody></table></section>"
    )


def slugify_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "report"
