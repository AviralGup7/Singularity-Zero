import json
from pathlib import Path
from typing import Any

from src.analysis.plugins import ANALYSIS_PLUGIN_SPECS, ANALYSIS_PLUGIN_SPECS_BY_KEY
from src.pipeline.storage import write_json

PLUGIN_ARTIFACT_DIRNAME = "analysis_plugins"
PLUGIN_MANIFEST_FILENAME = "manifest.json"


def plugin_artifact_dir(run_dir: Path) -> Path:
    return run_dir / PLUGIN_ARTIFACT_DIRNAME


def plugin_artifact_path(run_dir: Path, plugin_key: str) -> Path:
    spec = ANALYSIS_PLUGIN_SPECS_BY_KEY[plugin_key]
    return plugin_artifact_dir(run_dir) / f"{spec.slug}.json"


def plugin_manifest_path(run_dir: Path) -> Path:
    return plugin_artifact_dir(run_dir) / PLUGIN_MANIFEST_FILENAME


def write_plugin_artifacts(
    run_dir: Path, analysis_results: dict[str, list[dict[str, Any]]]
) -> None:
    artifact_dir = plugin_artifact_dir(run_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for spec in ANALYSIS_PLUGIN_SPECS:
        payload = analysis_results.get(spec.key, [])
        path = plugin_artifact_path(run_dir, spec.key)
        write_json(path, payload)
        manifest.append(
            {
                "key": spec.key,
                "slug": spec.slug,
                "label": spec.label,
                "path": str(path.relative_to(run_dir)),
                "count": len(payload),
            }
        )
    write_json(plugin_manifest_path(run_dir), manifest)


def load_plugin_artifact(run_dir: Path, plugin_key: str) -> list[dict[str, Any]]:
    paths = [
        plugin_artifact_path(run_dir, plugin_key),
        run_dir / f"{plugin_key}.json",
    ]
    for path in paths:
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(payload, list):
            return payload
    return []
