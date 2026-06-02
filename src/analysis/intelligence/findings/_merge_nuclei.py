"""Merge Nuclei findings into unified findings list."""

from typing import Any


def merge_nuclei(
    findings: list[dict[str, Any]],
    nuclei_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    nuclei_dedup_keys: set[str] = set()
    for existing in findings:
        existing_id = existing.get("id", "")
        if existing_id:
            nuclei_dedup_keys.add(existing_id)
        nuclei_dedup_keys.add(f"{existing.get('category', '')}|{existing.get('url', '')}")

    for nf in nuclei_findings:
        nf_id = nf.get("id", "")
        nf_category = nf.get("category", "")
        nf_url = nf.get("url", "")

        if nf_id and nf_id in nuclei_dedup_keys:
            continue
        if f"{nf_category}|{nf_url}" in nuclei_dedup_keys:
            continue

        if "module" not in nf:
            nf["module"] = "nuclei"
        if "endpoint_type" not in nf:
            nf["endpoint_type"] = "GENERAL"
        if "combined_signal" not in nf:
            nf["combined_signal"] = "nuclei"
        if "likely_exploitable_flow" not in nf:
            nf["likely_exploitable_flow"] = False
        if "next_step" not in nf:
            nf["next_step"] = (
                "Review Nuclei finding evidence and confirm the vulnerability manually."
            )
        if "explanation" not in nf:
            nf["explanation"] = (
                f"Nuclei template {nf.get('category', 'unknown')} matched at {nf_url}."
            )
        if "confidence_explanation" not in nf:
            nf["confidence_explanation"] = (
                "Nuclei automated detection with template-based matching."
            )

        findings.append(nf)
        if nf_id:
            nuclei_dedup_keys.add(nf_id)
        nuclei_dedup_keys.add(f"{nf_category}|{nf_url}")

    return findings
