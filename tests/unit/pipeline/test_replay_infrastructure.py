"""Tests for JobArtifactPackager and --replay infrastructure."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from src.pipeline.services.job_artifact_packager import (
    JobArtifactPackager,
    JobArtifactSnapshot,
    package_job,
    unpack_job,
)


@pytest.mark.unit
class TestJobArtifactSnapshot:
    def test_snapshot_defaults(self) -> None:
        snap = JobArtifactSnapshot(job_id="test123")
        assert snap.job_id == "test123"
        assert snap.git_commit_hash == ""
        assert snap.git_is_dirty is False
        assert snap.config_json == {}
        assert snap.scope_entries == []

    def test_snapshot_to_dict(self) -> None:
        snap = JobArtifactSnapshot(
            job_id="abc",
            git_commit_hash="abc123",
            git_is_dirty=True,
            config_json={"target_name": "example.com"},
            scope_entries=["example.com"],
        )
        d = snap.to_dict()
        assert d["job_id"] == "abc"
        assert d["git_commit_hash"] == "abc123"
        assert d["git_is_dirty"] is True
        assert d["config_json"] == {"target_name": "example.com"}
        assert d["scope_entries"] == ["example.com"]

    def test_snapshot_env_filter(self) -> None:
        os.environ["CYBER_TEST_VAR"] = "test_value"
        os.environ["OTHER_VAR"] = "should_not_appear"
        snap = JobArtifactSnapshot(job_id="env_test", env_vars=os.environ.copy())
        d = snap.to_dict()
        assert "CYBER_TEST_VAR" in d["env_vars"]
        assert "OTHER_VAR" not in d["env_vars"]
        del os.environ["CYBER_TEST_VAR"]
        del os.environ["OTHER_VAR"]


@pytest.mark.unit
class TestJobArtifactPackager:
    def test_capture_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = JobArtifactPackager(tmp)
            snap = p.capture_snapshot(
                job_id="job1",
                config_json={"target_name": "test.com"},
                scope_entries=["test.com"],
                config_template_path="/path/to/config.json",
                scope_file_path="/path/to/scope.txt",
            )
            assert snap.job_id == "job1"
            assert snap.config_json == {"target_name": "test.com"}
            assert snap.scope_entries == ["test.com"]
            assert snap.git_commit_hash in ("", "unknown")

    def test_package_and_unpackage_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp)
            packager = JobArtifactPackager(output_root)
            snap = packager.capture_snapshot(
                job_id="roundtrip_test",
                config_json={"base_url": "https://example.com", "mode": "safe"},
                scope_entries=["example.com", "www.example.com"],
            )

            archive = packager.package_snapshot(snap)

            assert archive.exists()
            assert archive.suffix == ".gz"
            assert ".tar" in archive.name

            restored_snap, extracted_dir = packager.unpackage_snapshot(archive)
            assert restored_snap.job_id == snap.job_id
            assert restored_snap.config_json == snap.config_json
            assert restored_snap.scope_entries == snap.scope_entries
            assert restored_snap.git_commit_hash == snap.git_commit_hash

            assert (extracted_dir / "artifacts" / "config.json").exists()
            assert (extracted_dir / "artifacts" / "scope.txt").exists()
            assert (extracted_dir / "artifacts" / "manifest.json").exists()

    def test_package_job_convenience(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp)
            archive = package_job(
                output_root=output_root,
                job_id="convenience_test",
                config_json={"target_name": "convenience.com"},
                scope_entries=["convenience.com"],
            )
            assert archive.exists()
            assert "convenience_test" in str(archive)

    def test_unpack_job_convenience(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp)
            archive = package_job(
                output_root=output_root,
                job_id="unpack_test",
                config_json={"target_name": "unpack.com"},
                scope_entries=["unpack.com"],
            )
            snap, extracted = unpack_job(archive)
            assert snap.job_id == "unpack_test"
            assert snap.config_json == {"target_name": "unpack.com"}


@pytest.mark.unit
class TestReplayArgumentParsing:
    def test_replay_arg_in_runner_support(self) -> None:
        from src.pipeline.runner_support import parse_args

        old_argv = ["--config", "c.json", "--scope", "s.txt", "--replay", "artifact.tar.gz"]
        import sys

        old = sys.argv
        sys.argv = ["prog"] + old_argv
        try:
            args = parse_args()
            assert args.replay_archive == Path("artifact.tar.gz")
            assert args.config == "c.json"
            assert args.scope == "s.txt"
        finally:
            sys.argv = old


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
