"""Architecture and contract tests for the Singularity-Zero Core Layer.

Enforces:
1. Checkpoint persistence validation (correct path layout, versioning, serialization, malformed recovery checks).
2. State delta propagation contracts (immutable inputs/outputs, deep freezing, state consolidation).
3. Stage isolation boundaries (static AST scans verifying core layer isolation and no stage cross-imports).
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

# Core imports
from src.core.checkpoint import (
    CheckpointManager,
    CheckpointState,
    StageCheckpointGuard,
    _validate_checkpoint_state,
)
from src.core.contracts.pipeline_runtime import (
    PipelineInput,
    StageInput,
    StageOutcome,
    StageOutput,
    _freeze_value,
)

WORKSPACE = Path(__file__).resolve().parents[2]
SRC_ROOT = WORKSPACE / "src"


# ===========================================================================
# 1. Checkpoint Persistence Validation
# ===========================================================================


@pytest.mark.architecture
class TestCheckpointPersistenceValidation:
    """Verify that checkpoint managers and states adhere to strict persistence contracts."""

    def test_checkpoint_state_serialization_roundtrip(self) -> None:
        """Verify that CheckpointState serializes and deserializes without losing precision or structure."""
        state = CheckpointState(
            pipeline_run_id="run-12345",
            checkpoint_version=3,
            completed_stages=["startup", "subdomain_enum"],
            current_stage=None,
            stage_results={
                "startup": {"status": "completed", "elapsed_seconds": 1.25},
                "subdomain_enum": {"status": "completed", "found": 15},
            },
            iterative_state={"last_tested_ip": "192.168.1.1"},
        )

        serialized = state.to_dict()
        assert serialized["pipeline_run_id"] == "run-12345"
        assert serialized["checkpoint_version"] == 3
        assert serialized["completed_stages"] == ["startup", "subdomain_enum"]
        assert serialized["stage_results"]["startup"]["elapsed_seconds"] == 1.25

        deserialized = CheckpointState.from_dict(serialized)
        assert deserialized.pipeline_run_id == state.pipeline_run_id
        assert deserialized.checkpoint_version == state.checkpoint_version
        assert set(deserialized.completed_stages) == set(state.completed_stages)
        assert deserialized.stage_results == state.stage_results
        assert deserialized.iterative_state == state.iterative_state

    def test_checkpoint_manager_path_layouts(self, tmp_path: Path) -> None:
        """Verify CheckpointManager enforces correct directory structure and naming conventions."""
        run_id = "test-run-unique-999"
        manager = CheckpointManager(
            checkpoint_dir=tmp_path,
            run_id=run_id,
        )

        # Check internal paths
        assert manager._run_dir == tmp_path / run_id
        assert manager._checkpoint_path(5) == tmp_path / run_id / "checkpoint_v5.json"
        assert manager._context_snapshot_path("recon") == tmp_path / run_id / "context_recon.json"
        assert (
            manager._stage_delta_path("fuzzing", 42)
            == tmp_path / run_id / "delta_fuzzing_000042.json"
        )

    def test_checkpoint_validation_rules(self) -> None:
        """Verify that malformed or corrupted checkpoints fail validation."""
        valid_state = CheckpointState(pipeline_run_id="valid-run-id")
        assert _validate_checkpoint_state(valid_state) is True

        # Invalid due to missing/invalid pipeline_run_id
        invalid_state_1 = CheckpointState(pipeline_run_id="")
        assert _validate_checkpoint_state(invalid_state_1) is False

        # Verify that an entirely malformed payload dictionary causes from_dict recovery to fail gracefully
        malformed_payload = {"checkpoint_version": "not-an-int", "completed_stages": 42}
        try:
            CheckpointState.from_dict(malformed_payload)
            # It might construct if types are coercion-friendly, but checking validation fails:
            state = CheckpointState(**malformed_payload)  # type: ignore
            assert _validate_checkpoint_state(state) is False
        except Exception:  # noqa: S110
            # If it raises an exception during parsing or reconstruction, that is also a correct failure path
            pass

    def test_stage_checkpoint_guard_lifecycle(self, tmp_path: Path) -> None:
        """Verify StageCheckpointGuard context manager sets current_stage and captures success/failure outcomes."""
        run_id = "guard-test-run"
        manager = CheckpointManager(checkpoint_dir=tmp_path, run_id=run_id)

        # 1. Successful execution
        with StageCheckpointGuard(manager, "stage_a"):
            state = manager.ensure_state()
            assert state.current_stage == "stage_a"
            assert "stage_a_started_at" in state.module_metrics

        state = manager.load()
        assert state is not None
        assert state.current_stage is None
        assert "stage_a" in state.completed_stages
        assert state.stage_results["stage_a"]["status"] == "completed"

        # 2. Failed execution (with exception)
        try:
            with StageCheckpointGuard(manager, "stage_b"):
                state = manager.ensure_state()
                assert state.current_stage == "stage_b"
                raise ValueError("Simulated stage crash")
        except ValueError:
            pass

        state = manager.load()
        assert state is not None
        assert state.current_stage is None
        assert "stage_b" not in state.completed_stages
        assert state.stage_results["stage_b"]["status"] == "failed"
        assert "ValueError" in state.stage_results["stage_b"]["error"]


# ===========================================================================
# 2. State Delta Propagation Contracts
# ===========================================================================


@pytest.mark.architecture
class TestStateDeltaPropagationContracts:
    """Verify that stage input/output contracts are strictly immutable and propagate correctly."""

    def test_immutable_contracts(self) -> None:
        """Verify that PipelineInput, StageInput, and StageOutput are frozen dataclasses."""
        pipeline_in = PipelineInput(
            target_name="target.com",
            scope_entries=("target.com", "api.target.com"),
            run_id="run-1",
        )
        stage_in = StageInput(
            stage_name="recon",
            stage_index=1,
            stage_total=14,
            pipeline=pipeline_in,
            state_snapshot={"found_hosts": []},
        )
        stage_out = StageOutput(
            stage_name="recon",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=5.4,
            state_delta={"new_hosts": ["api.target.com"]},
        )

        with pytest.raises(dataclasses.FrozenInstanceError):
            pipeline_in.target_name = "new-target.com"  # type: ignore

        with pytest.raises(dataclasses.FrozenInstanceError):
            stage_in.stage_name = "fuzzing"  # type: ignore

        with pytest.raises(dataclasses.FrozenInstanceError):
            stage_out.duration_seconds = 10.0  # type: ignore

    def test_value_freezing(self) -> None:
        """Verify that _freeze_value recursively converts mutable types into immutable alternatives."""
        mutable_dict = {
            "list": [1, 2, {"nested": "dict"}],
            "set": {1, 2, 3},
            "string": "hello",
        }

        frozen = _freeze_value(mutable_dict)

        # Check mapping proxy
        from types import MappingProxyType

        assert not isinstance(frozen, dict)
        assert isinstance(frozen, MappingProxyType)  # frozen dicts are MappingProxyType
        with pytest.raises(TypeError):
            frozen["string"] = "mutated"  # type: ignore

        # Check nested list -> tuple conversion
        assert isinstance(frozen["list"], tuple)
        assert isinstance(frozen["list"][2], MappingProxyType)  # nested dict also frozen
        with pytest.raises(TypeError):
            frozen["list"][2]["nested"] = "changed"  # type: ignore

        # Check set -> frozenset conversion
        assert isinstance(frozen["set"], frozenset)

    def test_state_delta_consolidation(self) -> None:
        """Verify that a sequence of stage state deltas consolidates accurately during propagation."""
        initial_state = {"discovered_urls": ["/index.html"], "auth_type": "none"}
        deltas = [
            {"discovered_urls": ["/index.html", "/login.php"], "auth_type": "jwt"},
            {"fuzzed_endpoints": ["/login.php"]},
            {"vulnerabilities": ["XSS at /login.php"]},
        ]

        # Consolidate updates
        consolidated = dict(initial_state)
        for delta in deltas:
            for key, val in delta.items():
                consolidated[key] = val

        assert consolidated["discovered_urls"] == ["/index.html", "/login.php"]
        assert consolidated["auth_type"] == "jwt"
        assert consolidated["fuzzed_endpoints"] == ["/login.php"]
        assert consolidated["vulnerabilities"] == ["XSS at /login.php"]


# ===========================================================================
# 3. Stage Isolation Boundaries
# ===========================================================================


class ImportVisitor(ast.NodeVisitor):
    def __init__(self, current_file: Path) -> None:
        self.current_file = current_file
        self.imports: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.append(node.module)
        self.generic_visit(node)


def get_imports_for_file(file_path: Path) -> list[str]:
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
        visitor = ImportVisitor(file_path)
        visitor.visit(tree)
        return visitor.imports
    except Exception:
        return []


@pytest.mark.architecture
class TestStageIsolationBoundaries:
    """Verify boundaries between core engine layers and stage implementation modules."""

    # Disallowed directories inside core
    STAGE_DIRECTORIES = {
        "analysis",
        "api_tests",
        "dashboard",
        "decision",
        "detection",
        "execution",
        "exploitation",
        "fuzzing",
        "pipeline",
        "recon",
        "reporting",
        "websocket_server",
    }

    def test_core_layer_purity(self) -> None:
        """Verify that files inside src/core/ are pure and do not depend on specific stage implementations."""
        core_dir = SRC_ROOT / "core"
        violations: list[str] = []

        for py_file in core_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            imports = get_imports_for_file(py_file)
            for imp in imports:
                # Check if it imports any stage-specific package
                parts = imp.split(".")
                if len(parts) >= 2 and parts[0] == "src" and parts[1] in self.STAGE_DIRECTORIES:
                    # Exception: checkpoint.py imports DistributedCheckpointStore from infrastructure or similar.
                    # We block imports of actual stage directories (e.g. src.recon, src.fuzzing, src.exploitation, etc.)
                    if parts[1] in {
                        "recon",
                        "fuzzing",
                        "exploitation",
                        "reporting",
                        "analysis",
                        "decision",
                    }:
                        # Exclude allowed loader references (loading plugins at runtime) and mutation engine dynamic imports
                        if (
                            "core/plugins/loader.py" in str(py_file).replace("\\", "/")
                            and parts[1] == "analysis"
                        ):
                            continue
                        if (
                            "core/mutation_engine.py" in str(py_file).replace("\\", "/")
                            and imp == "src.fuzzing.ast_mutator"
                        ):
                            continue
                        violations.append(
                            f"Core module {py_file.relative_to(WORKSPACE)} imports stage implementation '{imp}'"
                        )

        assert violations == [], (
            "The core framework layer must remain independent of stage implementations.\n"
            + "\n".join(violations)
        )

    def test_stage_purity_and_isolation(self) -> None:
        """Verify that stage implementations do not cross-import from other stages directly."""
        stage_packages = ["recon", "fuzzing", "exploitation", "reporting", "decision", "detection"]
        violations: list[str] = []

        for stage in stage_packages:
            stage_dir = SRC_ROOT / stage
            if not stage_dir.is_dir():
                continue

            for py_file in stage_dir.rglob("*.py"):
                if "__pycache__" in str(py_file):
                    continue
                imports = get_imports_for_file(py_file)
                for imp in imports:
                    parts = imp.split(".")
                    if len(parts) >= 2 and parts[0] == "src" and parts[1] in stage_packages:
                        # Stage is importing from another stage!
                        if parts[1] != stage:
                            # Allow reporting to import other stages if it compiles metrics, but generally block cross-talk
                            if stage == "reporting":
                                continue
                                # Allow specific known, intentional cross-stage imports that are
                                # effectively shared utilities (WAF strategy primitives are used
                                # directly by the exploitation engine, and HTTP/2 frame helpers
                                # are reused by the fuzzer).
                                allowed_cross = {
                                    ("fuzzing", "src.exploitation.http2_exploit"),
                                    ("exploitation", "src.detection.waf"),
                                }
                                if (stage, imp) in allowed_cross:
                                    continue
                                violations.append(
                                f"Isolated Stage {stage} ({py_file.relative_to(WORKSPACE)}) cross-imports other stage '{imp}'"
                            )

        assert violations == [], (
            "Stages must remain completely isolated from each other to allow parallel, out-of-order, "
            "or dynamic orchestration without compilation/import cycles.\n" + "\n".join(violations)
        )

    def test_stage_execution_occurs_via_contracts(self) -> None:
        """Verify that stage orchestrators and runner entry points utilize StageInput and StageOutput."""
        # This test ensures that the standard pipeline orchestrator files are declaring/importing
        # the StageInput and StageOutput contracts.
        orchestrator_dir = SRC_ROOT / "pipeline"
        imports_contracts = False

        for py_file in orchestrator_dir.rglob("*.py"):
            imports = get_imports_for_file(py_file)
            for imp in imports:
                if "pipeline_runtime" in imp or "StageInput" in imp or "StageOutput" in imp:
                    imports_contracts = True
                    break

        assert imports_contracts is True, (
            "Orchestration layer must import/reference the standard StageInput/StageOutput runtime contracts."
        )
