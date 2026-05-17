"""Pipeline output store for persisting run artifacts and results.

Provides PipelineOutputStore class for writing pipeline outputs (subdomains,
live hosts, URLs, findings, reports) to structured run directories with
optional artifact manifest generation and alias deduplication.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.core.frontier.ghost_vfs import GhostVFS
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.storage import ArtifactStore
from src.core.storage.factory import create_artifact_store
from src.core.utils import run_dir_stamp
from src.pipeline.storage import (
    format_json,
    format_jsonl,
    format_lines,
    format_ranked_lines,
)

ARTIFACT_ALIASES = {
    "validation_results.json": ["custom_validation_results.json"],
}

logger = get_pipeline_logger(__name__)


class PipelineOutputStore:
    """Manages output persistence with Ghost-VFS anti-forensic support."""

    def __init__(
        self,
        artifact_store: ArtifactStore,
        local_run_dir: Path,
        target_name: str,
        run_id: str,
        *,
        dedupe_aliases: bool = True,
        write_artifact_manifest: bool = True,
        ghost_vfs: GhostVFS | None = None,
    ):
        self._store = artifact_store
        self.local_run_dir = local_run_dir
        self.target_name = target_name
        self.run_id = run_id
        self.run_prefix = f"{target_name}/{run_id}"
        self.dedupe_aliases = dedupe_aliases
        self.write_artifact_manifest = write_artifact_manifest
        self._ghost_vfs = ghost_vfs

        if self._ghost_vfs:
            logger.info("OutputStore: [GHOST-MODE] Volatile RAM-only storage active.")

    @classmethod
    def create(
        cls,
        output_root: Path,
        target_name: str,
        output_settings: dict[str, Any] | None = None,
        storage_config: dict[str, Any] | None = None,
    ) -> PipelineOutputStore:
        settings = output_settings or {}
        run_id = run_dir_stamp()
        target_root = (output_root / target_name).resolve()
        local_run_dir = (target_root / run_id).resolve()

        ghost_vfs = None
        if storage_config and storage_config.get("anti_forensic_mode"):
            ghost_vfs = GhostVFS()
        else:
            local_run_dir.mkdir(parents=True, exist_ok=True)

        artifact_store = create_artifact_store(storage_config, output_root)

        return cls(
            artifact_store,
            local_run_dir,
            target_name,
            run_id,
            dedupe_aliases=bool(settings.get("dedupe_aliases", True)),
            write_artifact_manifest=bool(settings.get("write_artifact_manifest", True)),
            ghost_vfs=ghost_vfs,
        )

    @property
    def target_root(self) -> Path:
        return self.local_run_dir.parent

    @property
    def run_dir(self) -> Path:
        return self.local_run_dir

    def _get_key(self, filename: str) -> str:
        return f"{self.run_prefix}/{filename}"

    def write_scope(self, scope_entries: list[str]) -> None:
        self.write_text("scope.txt", format_lines(scope_entries))

    def write_subdomains(self, subdomains: set[str]) -> None:
        self.write_text("subdomains.txt", format_lines(subdomains))

    def write_live_hosts(self, live_records: list[dict[str, Any]], live_hosts: set[str]) -> None:
        self.write_text("live_hosts.jsonl", format_jsonl(live_records))
        self.write_text("live_hosts.txt", format_lines(live_hosts))

    def write_urls(self, urls: set[str]) -> None:
        self.write_text("urls.txt", format_lines(urls))

    def write_parameters(self, parameters: set[str]) -> None:
        self.write_text("parameters.txt", format_lines(parameters))

    def write_priority_endpoints(self, priority_urls: list[str]) -> None:
        self.write_text("priority_endpoints.txt", format_ranked_lines(priority_urls))

    def write_nuclei_output(self, label: str, output: str) -> None:
        if not output:
            return
        filename = "nuclei.txt" if not label else f"nuclei_{label}.txt"
        self.write_text(filename, output)

    def write_text(self, filename: str, content: str) -> str:
        """Atomic write to either Disk or Ghost-VFS."""
        if self._ghost_vfs:
            # RAM-only encrypted path
            path = f"{self.run_prefix}/{filename}"
            self._ghost_vfs.write_file(path, content)
            return f"ghost://{path}"

        # Standard physical path
        local_path = self.local_run_dir / filename
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(content, encoding="utf-8")

        key = self._get_key(filename)
        return self._store.put(key, content.encode("utf-8"))

    def write_json_artifact(self, filename: str, payload: dict[str, Any] | list[Any]) -> str:
        content = format_json(payload)
        key = self.write_text(filename, content)
        for alias_name in ARTIFACT_ALIASES.get(filename, []):
            self.write_text(alias_name, content)
        return key

    def upload_file(self, local_path: Path, filename: str | None = None) -> str:
        """Upload an existing local file to the artifact store."""
        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        fname = filename or local_path.name
        key = self._get_key(fname)
        return self._store.put(key, local_path.read_bytes())

    def persist_outputs(
        self,
        summary: dict[str, Any],
        diff_summary: dict[str, Any] | None,
        screenshots: list[dict[str, Any]],
        analysis_results: dict[str, list[dict[str, Any]]],
        merged_findings: list[dict[str, Any]],
    ) -> None:
        if diff_summary:
            self.write_json_artifact("diff_summary.json", diff_summary)
        if screenshots:
            self.write_json_artifact("screenshots.json", screenshots)
        for label, findings in analysis_results.items():
            self.write_json_artifact(f"{label}.json", findings)
        self.write_json_artifact("findings.json", merged_findings)
        self.write_json_artifact("verified_exploits.json", summary.get("verified_exploits", []))
        self.write_json_artifact("validation_results.json", summary.get("validation_results", {}))
        self.write_json_artifact("run_summary.json", summary)
        if self.write_artifact_manifest:
            self.write_json_artifact(
                "artifacts.json",
                self._build_artifact_manifest(summary, diff_summary, screenshots, analysis_results),
            )

    def _build_artifact_manifest(
        self,
        summary: dict[str, Any],
        diff_summary: dict[str, Any] | None,
        screenshots: list[dict[str, Any]],
        analysis_results: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        analysis_files = {
            f"{label}.json": len(findings) for label, findings in analysis_results.items()
        }
        return {
            "run_summary": "run_summary.json",
            "findings": "findings.json",
            "validation_results": "validation_results.json",
            "aliases": ARTIFACT_ALIASES,
            "analysis_artifacts": analysis_files,
            "has_diff_summary": bool(diff_summary),
            "has_screenshots": bool(screenshots),
            "top_level_counts": summary.get("counts", {}),
        }

    def _write_alias(self, source: Path, alias: Path, payload: dict[str, Any] | list[Any]) -> None:
        try:
            alias.unlink()
        except FileNotFoundError:
            pass
        except PermissionError:
            pass
        if self.dedupe_aliases:
            try:
                os.link(source, alias)
                return
            except OSError:
                pass
        alias.write_text(json.dumps(payload, indent=2), encoding="utf-8")
