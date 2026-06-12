"""SBOM generation stage."""

from __future__ import annotations

import json
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

logger = get_pipeline_logger(__name__)


def _merge_sbom_fragments(fragments: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [],
        "metadata": {},
    }
    seen = set()
    for key, fragment in fragments.items():
        if not isinstance(fragment, dict):
            continue
        for comp in fragment.get("components", []):
            comp_name = comp.get("name", "")
            comp_version = comp.get("version", "")
            comp_purl = comp.get("purl", "")
            identity = comp_purl or f"{comp_name}@{comp_version}"
            if identity in seen:
                continue
            seen.add(identity)
            merged["components"].append(comp)
    return merged


async def run_sbom_generate_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: SBOM generation by merging fragments from prior stages."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("sbom_generate", config, ctx)

    stage_started = time.monotonic()

    file_manifest = getattr(ctx.result, "file_manifest", None) or {}
    dependency_tree = getattr(ctx.result, "dependency_tree", None) or {}
    sbom_fragment = getattr(ctx.result, "sbom_fragment", None) or {}

    if not any([file_manifest, dependency_tree, sbom_fragment]):
        ctx.mark_stage_skipped("sbom_generate", reason="no_sbom_inputs")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sbom_generate",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "no_sbom_inputs"},
            state_delta={},
        )

    emit_progress("sbom_generate", "Generating unified SBOM", 50)

    try:
        fragments: dict[str, Any] = {}
        if sbom_fragment:
            fragments["sca"] = sbom_fragment
        if dependency_tree:
            fragments["deps"] = dependency_tree

        sbom = _merge_sbom_fragments(fragments)
        sbom_cyclonedx = dict(sbom)
        sbom_spdx: dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Pipeline SBOM",
            "documentNamespace": "",
            "creationInfo": {"created": "", "creators": ["tool:pipeline"]},
            "packages": [],
        }
        for comp in sbom.get("components", []):
            pkg = {
                "SPDXID": comp.get("purl", comp.get("name", "UNKNOWN")),
                "name": comp.get("name", ""),
                "versionInfo": comp.get("version", ""),
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            sbom_spdx["packages"].append(pkg)

        sbom_path = ctx.output_store.run_dir / "sbom.json"
        sbom_cyclonedx_path = ctx.output_store.run_dir / "sbom_cyclonedx.json"
        sbom_spdx_path = ctx.output_store.run_dir / "sbom_spdx.json"

        for path, data in [
            (sbom_path, sbom),
            (sbom_cyclonedx_path, sbom_cyclonedx),
            (sbom_spdx_path, sbom_spdx),
        ]:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        ctx.mark_stage_complete("sbom_generate")
        duration = round(time.monotonic() - stage_started, 2)
        state_delta = {
            "sbom": sbom,
            "sbom_cyclonedx": sbom_cyclonedx,
            "sbom_spdx": sbom_spdx,
        }
        return StageOutput(
            stage_name="sbom_generate",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "ok",
                "components": len(sbom.get("components", [])),
                "cyclonedx_path": str(sbom_cyclonedx_path),
                "spdx_path": str(sbom_spdx_path),
            },
            state_delta=state_delta,
        )

    except Exception as exc:
        logger.error("SBOM generation failed: %s", exc)
        ctx.mark_stage_failed("sbom_generate", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sbom_generate",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
