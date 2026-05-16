"""Job artifact packager for run replay and verification.

Creates a self-contained tar.gz archive of all inputs needed to reproduce
a pipeline run identically: config.json, scope.txt, git commit hash, and
environment variables.

Run with: python -m src.pipeline.services.job_artifact_packager <job_id> <output_root>
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _safe_extract(tar: tarfile.TarFile, extract_dir: Path) -> None:
    """Safely extract tarfile, preventing path traversal attacks."""
    extract_dir_abs = os.path.abspath(extract_dir)
    for member in tar.getmembers():
        member_path = os.path.abspath(os.path.join(extract_dir_abs, member.name))
        if not member_path.startswith(extract_dir_abs + os.sep):
            raise ValueError(f"Path traversal attempt detected: {member.name}")
    tar.extractall(extract_dir, filter="data")


@dataclass
class JobArtifactSnapshot:
    """Immutable snapshot of all inputs needed to reproduce a run."""

    job_id: str
    created_at_epoch: float = field(default_factory=time.time)
    git_commit_hash: str = ""
    git_is_dirty: bool = False
    config_json: dict[str, Any] = field(default_factory=dict)
    scope_entries: list[str] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    config_template_path: str = ""
    scope_file_path: str = ""
    schema_version: str = "1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "created_at_epoch": self.created_at_epoch,
            "git_commit_hash": self.git_commit_hash,
            "git_is_dirty": self.git_is_dirty,
            "config_json": self.config_json,
            "scope_entries": self.scope_entries,
            "env_vars": {k: v for k, v in self.env_vars.items() if k.startswith("CYBER_")},
            "config_template_path": self.config_template_path,
            "scope_file_path": self.scope_file_path,
        }


class JobArtifactPackager:
    """Package pipeline run artifacts into a replayable tar.gz archive.

    Before a run, snapshots config, scope file, current git commit hash, and
    relevant environment variables into a tar.gz stored alongside the
    run output in `_launcher/<job_id>/artifact_pack.tar.gz`.
    """

    def __init__(self, output_root: Path | str) -> None:
        self.output_root = Path(output_root).resolve()

    def capture_snapshot(
        self,
        job_id: str,
        config_json: dict[str, Any],
        scope_entries: list[str],
        *,
        config_template_path: str = "",
        scope_file_path: str = "",
    ) -> JobArtifactSnapshot:
        """Capture the current state of all run inputs.

        Args:
            job_id: Unique job identifier.
            config_json: The loaded config dict.
            scope_entries: List of scope entry strings.
            config_template_path: Path to the config template used.
            scope_file_path: Path to the scope file used.

        Returns:
            JobArtifactSnapshot with git hash, config, scope, and env.
        """
        git_hash, git_dirty = self._git_info()
        env_subset = self._capture_env()

        return JobArtifactSnapshot(
            job_id=job_id,
            git_commit_hash=git_hash,
            git_is_dirty=git_dirty,
            config_json=dict(config_json),
            scope_entries=list(scope_entries),
            config_template_path=config_template_path,
            scope_file_path=scope_file_path,
            env_vars=env_subset,
        )

    def package_snapshot(
        self,
        snapshot: JobArtifactSnapshot,
        destination: Path | None = None,
    ) -> Path:
        """Write a snapshot to a gzip'd tar archive.

        The archive contains:
          artifacts/config.json
          artifacts/scope.txt
          artifacts/manifest.json (full snapshot metadata)

        Args:
            snapshot: JobArtifactSnapshot to package.
            destination: Optional output path. Defaults to
                <output_root>/_launcher/<job_id>/artifact_pack.tar.gz.

        Returns:
            Path to the created archive.
        """
        launcher_dir = self.output_root / "_launcher" / snapshot.job_id
        launcher_dir.mkdir(parents=True, exist_ok=True)

        if destination is None:
            destination = launcher_dir / "artifact_pack.tar.gz"

        manifest_json = json.dumps(snapshot.to_dict(), indent=2, sort_keys=True)

        import tarfile

        with tarfile.open(destination, "w:gz") as tar:
            import io

            config_data = json.dumps(snapshot.config_json, indent=2, sort_keys=True)
            config_info = tarfile.TarInfo(name="artifacts/config.json")
            config_info.size = len(config_data.encode("utf-8"))
            tar.addfile(config_info, fileobj=io.BytesIO(config_data.encode("utf-8")))

            scope_data = "\n".join(snapshot.scope_entries) + "\n"
            scope_info = tarfile.TarInfo(name="artifacts/scope.txt")
            scope_info.size = len(scope_data.encode("utf-8"))
            tar.addfile(scope_info, fileobj=io.BytesIO(scope_data.encode("utf-8")))

            manifest_info = tarfile.TarInfo(name="artifacts/manifest.json")
            manifest_info.size = len(manifest_json.encode("utf-8"))
            tar.addfile(manifest_info, fileobj=io.BytesIO(manifest_json.encode("utf-8")))

        return destination

    def unpackage_snapshot(self, archive_path: Path) -> tuple[JobArtifactSnapshot, Path]:
        """Extract a snapshot archive to a temporary directory.

        Args:
            archive_path: Path to the .tar.gz archive.

        Returns:
            Tuple of (JobArtifactSnapshot, Path to extracted directory).
        """
        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")

        extract_dir = archive_path.parent / f"{archive_path.stem}.unpacked"
        extract_dir.mkdir(parents=True, exist_ok=True)

        with tarfile.open(archive_path, "r:gz") as tar:
            _safe_extract(tar, extract_dir)

        manifest_path = extract_dir / "artifacts" / "manifest.json"
        if not manifest_path.exists():
            raise ValueError("Invalid archive: missing manifest.json")

        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        snapshot = JobArtifactSnapshot(
            job_id=manifest_data["job_id"],
            created_at_epoch=manifest_data.get("created_at_epoch", 0.0),
            git_commit_hash=manifest_data.get("git_commit_hash", ""),
            git_is_dirty=manifest_data.get("git_is_dirty", False),
            config_json=manifest_data.get("config_json", {}),
            scope_entries=manifest_data.get("scope_entries", []),
            env_vars=manifest_data.get("env_vars", {}),
            config_template_path=manifest_data.get("config_template_path", ""),
            scope_file_path=manifest_data.get("scope_file_path", ""),
            schema_version=manifest_data.get("schema_version", "1"),
        )
        return snapshot, extract_dir

    def verify_parity(
        self,
        snapshot: JobArtifactSnapshot,
        new_run_manifest: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare a replay run's manifest against the archived baseline.

        Args:
            snapshot: The baseline JobArtifactSnapshot.
            new_run_manifest: The forensic manifest of the replay run
                (from build_launcher_replay_manifest).

        Returns:
            dict with parity results: matches, changed_fields, warning_delta, etc.
        """
        from src.dashboard.launcher_forensics import compare_launcher_replay_manifests

        baseline_manifest = {
            "schema_version": 1,
            "job_id": snapshot.job_id,
            "config_summary": {
                "base_url": snapshot.config_json.get("base_url", ""),
                "target_name": snapshot.config_json.get("target_name", ""),
                "mode": snapshot.config_json.get("mode", ""),
            },
            "runtime_signal_truth": {
                "git_commit_hash": snapshot.git_commit_hash,
            },
        }

        comparison = compare_launcher_replay_manifests(baseline_manifest, new_run_manifest)

        return comparison

    def _git_info(self) -> tuple[str, bool]:
        """Return current git commit hash and dirty flag."""
        try:
            hash_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=self.output_root,
            )
            commit_hash = hash_result.stdout.strip()[:12]

            status_result = subprocess.run(
                ["git", "status", "--porcelain"],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=10,
                cwd=self.output_root,
            )
            is_dirty = bool(status_result.stdout.strip())

            return commit_hash, is_dirty
        except Exception:
            return "unknown", False

    def _capture_env(self) -> dict[str, str]:
        """Capture CYBER_-prefixed environment variables."""
        return {k: v for k, v in os.environ.items() if k.startswith("CYBER_")}


def package_job(
    output_root: Path | str,
    job_id: str,
    config_json: dict[str, Any],
    scope_entries: list[str],
    *,
    config_template_path: str = "",
    scope_file_path: str = "",
    archive_path: Path | None = None,
) -> Path:
    """Convenience function: capture and package a job's artifacts.

    Returns:
        Path to the created tar.gz archive.
    """
    packager = JobArtifactPackager(output_root)
    snapshot = packager.capture_snapshot(
        job_id,
        config_json,
        scope_entries,
        config_template_path=config_template_path,
        scope_file_path=scope_file_path,
    )
    return packager.package_snapshot(snapshot, destination=archive_path)


def unpack_job(
    archive_path: Path,
) -> tuple[JobArtifactSnapshot, Path]:
    """Convenience function: unpack a job artifact archive.

    Returns:
        Tuple of (JobArtifactSnapshot, path to extracted directory).
    """
    packager = JobArtifactPackager(archive_path.parent)
    return packager.unpackage_snapshot(archive_path)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <job_id> <output_root>")
        sys.exit(1)

    job_id = sys.argv[1]
    output_root = Path(sys.argv[2]).resolve()

    packager = JobArtifactPackager(output_root)
    launcher_dir = output_root / "_launcher" / job_id

    config_path = launcher_dir / "config.json"
    scope_path = launcher_dir / "scope.txt"

    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = json.loads(config_path.read_text(encoding="utf-8"))
    scope = [line.strip() for line in scope_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    archive_path = packager.package_snapshot(
        packager.capture_snapshot(
            job_id,
            config,
            scope,
            config_template_path=str(config_path),
            scope_file_path=str(scope_path),
        )
    )
    print(f"Archived to: {archive_path}")
    print(f"Size: {archive_path.stat().st_size:,} bytes")

    snapshot, extracted = packager.unpackage_snapshot(archive_path)
    print(f"Verified unpack: job_id={snapshot.job_id} git={snapshot.git_commit_hash}")
