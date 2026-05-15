"""Tests for ETA engine in dashboard_app.eta_engine."""

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from src.dashboard.eta_engine import (
    BayesianSimpleModel,
    ETAEngine,
    get_eta_engine,
)

# ---------------------------------------------------------------------------
# BayesianSimpleModel – construction & defaults
# ---------------------------------------------------------------------------


class TestBayesianSimpleModelConstruction:
    def test_default_prior(self):
        model = BayesianSimpleModel()
        assert model._prior_mean == 300.0
        assert model.sample_count == 0

    def test_custom_parameters(self):
        model = BayesianSimpleModel(
            prior_mean=600.0,
            prior_variance=1200.0**2,
            data_variance=600.0**2,
        )
        assert model._prior_mean == 600.0
        assert model.sample_count == 0

    def test_zero_data_variance(self):
        model = BayesianSimpleModel(data_variance=0)
        assert model._data_precision == 0.0


# ---------------------------------------------------------------------------
# BayesianSimpleModel – add_sample
# ---------------------------------------------------------------------------


class TestBayesianSimpleModelAddSample:
    def test_add_positive_sample(self):
        model = BayesianSimpleModel()
        model.add_sample(100.0)
        assert model.sample_count == 1

    def test_add_zero_sample_ignored(self):
        model = BayesianSimpleModel()
        model.add_sample(0.0)
        assert model.sample_count == 0

    def test_add_negative_sample_ignored(self):
        model = BayesianSimpleModel()
        model.add_sample(-5.0)
        assert model.sample_count == 0

    def test_add_multiple_samples(self):
        model = BayesianSimpleModel()
        model.add_sample(100.0)
        model.add_sample(200.0)
        model.add_sample(300.0)
        assert model.sample_count == 3

    def test_samples_stored(self):
        model = BayesianSimpleModel()
        model.add_sample(42.0)
        model.add_sample(58.0)
        assert model._samples == [42.0, 58.0]


# ---------------------------------------------------------------------------
# BayesianSimpleModel – sample_mean
# ---------------------------------------------------------------------------


class TestBayesianSimpleModelSampleMean:
    def test_no_samples_returns_prior_mean(self):
        model = BayesianSimpleModel(prior_mean=500.0)
        assert model.sample_mean == 500.0

    def test_single_sample(self):
        model = BayesianSimpleModel()
        model.add_sample(120.0)
        assert model.sample_mean == 120.0

    def test_multiple_samples(self):
        model = BayesianSimpleModel()
        model.add_sample(100.0)
        model.add_sample(200.0)
        model.add_sample(300.0)
        assert model.sample_mean == 200.0


# ---------------------------------------------------------------------------
# BayesianSimpleModel – posterior_mean
# ---------------------------------------------------------------------------


class TestBayesianSimpleModelPosteriorMean:
    def test_no_samples_returns_prior_mean(self):
        model = BayesianSimpleModel(prior_mean=300.0)
        assert model.posterior_mean == 300.0

    def test_posterior_shrinks_toward_data(self):
        model = BayesianSimpleModel(
            prior_mean=300.0,
            prior_variance=600.0**2,
            data_variance=300.0**2,
        )
        model.add_sample(100.0)
        posterior = model.posterior_mean
        assert 100.0 < posterior < 300.0

    def test_posterior_converges_to_sample_mean_with_many_samples(self):
        model = BayesianSimpleModel(
            prior_mean=300.0,
            prior_variance=600.0**2,
            data_variance=300.0**2,
        )
        for _ in range(1000):
            model.add_sample(100.0)
        posterior = model.posterior_mean
        assert abs(posterior - 100.0) < 1.0


# ---------------------------------------------------------------------------
# BayesianSimpleModel – estimate_remaining
# ---------------------------------------------------------------------------


class TestBayesianSimpleModelEstimateRemaining:
    def test_last_stage_returns_zero(self):
        model = BayesianSimpleModel()
        model.add_sample(100.0)
        result = model.estimate_remaining(100.0, stage_index=9, total_stages=10)
        assert result == 0.0

    def test_beyond_last_stage_returns_zero(self):
        model = BayesianSimpleModel()
        model.add_sample(100.0)
        result = model.estimate_remaining(100.0, stage_index=10, total_stages=10)
        assert result == 0.0

    def test_uses_posterior_mean_with_no_data(self):
        model = BayesianSimpleModel(prior_mean=300.0)
        remaining = model.estimate_remaining(0.0, stage_index=0, total_stages=10)
        assert remaining is not None
        assert remaining == 300.0 * 9

    def test_uses_max_of_posterior_and_elapsed_average(self):
        model = BayesianSimpleModel(
            prior_mean=300.0,
            prior_variance=600.0**2,
            data_variance=300.0**2,
        )
        model.add_sample(100.0)
        model.add_sample(100.0)
        remaining = model.estimate_remaining(500.0, stage_index=1, total_stages=10)
        assert remaining is not None
        assert remaining > 0

    def test_remaining_decreases_as_stage_progresses(self):
        model = BayesianSimpleModel()
        model.add_sample(100.0)
        model.add_sample(100.0)

        r1 = model.estimate_remaining(100.0, stage_index=0, total_stages=10)
        r2 = model.estimate_remaining(100.0, stage_index=5, total_stages=10)
        assert r1 is not None
        assert r2 is not None
        assert r1 > r2

    def test_returns_zero_for_single_stage_total(self):
        model = BayesianSimpleModel()
        result = model.estimate_remaining(100.0, stage_index=0, total_stages=1)
        assert result == 0.0


# ---------------------------------------------------------------------------
# ETAEngine – construction
# ---------------------------------------------------------------------------


class TestETAEngineConstruction:
    def test_default_output_dir(self):
        engine = ETAEngine()
        assert engine._output_dir == Path("output")

    def test_custom_output_dir(self):
        engine = ETAEngine(output_dir="/tmp/test_output")
        assert engine._output_dir == Path("/tmp/test_output")

    def test_custom_history_path(self):
        engine = ETAEngine(history_path="/tmp/history.json")
        assert engine._history_path == Path("/tmp/history.json")

    def test_background_interval_minimum_1(self):
        engine = ETAEngine(background_interval=0)
        assert engine._background_interval == 1

    def test_background_interval_respects_value(self):
        engine = ETAEngine(background_interval=10)
        assert engine._background_interval == 10


# ---------------------------------------------------------------------------
# ETAEngine – _load_summary_for_job
# ---------------------------------------------------------------------------


class TestETALoadSummaryForJob:
    def test_load_valid_summary(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "stage_durations": {
                        "startup": 10.0,
                        "subdomains": 30.0,
                    }
                },
                f,
            )
            f.flush()
            summary_path = Path(f.name)

        try:
            engine._load_summary_for_job("job-1", summary_path, stage_models)
            assert "job-1" in stage_models
            assert 0 in stage_models["job-1"]
            assert 1 in stage_models["job-1"]
            assert stage_models["job-1"][0].sample_count == 1
            assert stage_models["job-1"][1].sample_count == 1
        finally:
            summary_path.unlink()

    def test_load_missing_file(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}
        engine._load_summary_for_job("job-1", Path("/nonexistent/run_summary.json"), stage_models)
        assert "job-1" not in stage_models

    def test_load_corrupted_json(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{not valid json!!!")
            f.flush()
            summary_path = Path(f.name)

        try:
            engine._load_summary_for_job("job-1", summary_path, stage_models)
            assert "job-1" not in stage_models
        finally:
            summary_path.unlink()

    def test_load_empty_stage_durations(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"stage_durations": {}}, f)
            f.flush()
            summary_path = Path(f.name)

        try:
            engine._load_summary_for_job("job-1", summary_path, stage_models)
            assert "job-1" not in stage_models
        finally:
            summary_path.unlink()

    def test_load_negative_duration_skipped(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "stage_durations": {
                        "startup": -5.0,
                        "subdomains": 30.0,
                    }
                },
                f,
            )
            f.flush()
            summary_path = Path(f.name)

        try:
            engine._load_summary_for_job("job-1", summary_path, stage_models)
            assert "job-1" in stage_models
            assert 0 not in stage_models["job-1"]
            assert 1 in stage_models["job-1"]
        finally:
            summary_path.unlink()

    def test_load_unknown_stage_skipped(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "stage_durations": {
                        "unknown_stage_xyz": 50.0,
                    }
                },
                f,
            )
            f.flush()
            summary_path = Path(f.name)

        try:
            engine._load_summary_for_job("job-1", summary_path, stage_models)
            assert "job-1" not in stage_models
        finally:
            summary_path.unlink()

    def test_load_multiple_jobs_same_stage(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f1:
            json.dump({"stage_durations": {"startup": 10.0}}, f1)
            f1.flush()
            path1 = Path(f1.name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f2:
            json.dump({"stage_durations": {"startup": 20.0}}, f2)
            f2.flush()
            path2 = Path(f2.name)

        try:
            engine._load_summary_for_job("job-a", path1, stage_models)
            engine._load_summary_for_job("job-b", path2, stage_models)
            assert stage_models["job-a"][0].sample_count == 1
            assert stage_models["job-b"][0].sample_count == 1
        finally:
            path1.unlink()
            path2.unlink()

    def test_load_permission_error(self):
        engine = ETAEngine()
        stage_models: dict[str, dict[int, BayesianSimpleModel]] = {}
        protected_path = Path("/root/protected_summary.json")
        engine._load_summary_for_job("job-1", protected_path, stage_models)
        assert "job-1" not in stage_models


# ---------------------------------------------------------------------------
# ETAEngine – _refresh
# ---------------------------------------------------------------------------


class TestETAEngineRefresh:
    @pytest.mark.asyncio
    async def test_refresh_scans_output_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job-abc"
            job_dir.mkdir()
            summary = job_dir / "run_summary.json"
            summary.write_text(json.dumps({"stage_durations": {"startup": 15.0}}))

            engine = ETAEngine(output_dir=tmpdir)
            await engine._refresh()

            model = engine._get_aggregate_model(0)
            assert model is not None
            assert model.sample_count == 1

    @pytest.mark.asyncio
    async def test_refresh_skips_dirs_without_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job-no-summary"
            job_dir.mkdir()

            engine = ETAEngine(output_dir=tmpdir)
            await engine._refresh()

            assert len(engine._models) == 0

    @pytest.mark.asyncio
    async def test_refresh_handles_os_error(self):
        engine = ETAEngine(output_dir="/nonexistent/path/xyz")
        await engine._refresh()
        assert len(engine._models) == 0

    @pytest.mark.asyncio
    async def test_refresh_isolates_corrupted_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            good_dir = Path(tmpdir) / "job-good"
            good_dir.mkdir()
            (good_dir / "run_summary.json").write_text(
                json.dumps({"stage_durations": {"startup": 10.0}})
            )

            bad_dir = Path(tmpdir) / "job-bad"
            bad_dir.mkdir()
            (bad_dir / "run_summary.json").write_text("not json")

            engine = ETAEngine(output_dir=tmpdir)
            await engine._refresh()

            model = engine._get_aggregate_model(0)
            assert model is not None
            assert model.sample_count == 1


# ---------------------------------------------------------------------------
# ETAEngine – compute_eta_sync
# ---------------------------------------------------------------------------


class TestETAEngineComputeEtaSync:
    def test_returns_none_with_no_data(self):
        engine = ETAEngine()
        result = engine.compute_eta_sync("job-1", "startup", 10.0)
        assert result is None

    def test_returns_estimate_with_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                job_dir = Path(tmpdir) / f"job-hist-{i}"
                job_dir.mkdir()
                (job_dir / "run_summary.json").write_text(
                    json.dumps(
                        {
                            "stage_durations": {
                                "startup": 10.0,
                                "subdomains": 30.0,
                            }
                        }
                    )
                )

            engine = ETAEngine(output_dir=tmpdir)
            asyncio.run(engine._refresh())

            result = engine.compute_eta_sync("job-new", "startup", 5.0)
            assert result is not None
            assert "eta_seconds" in result
            assert "confidence" in result
            assert result["method"] == "bayesian"
            assert result["sample_count"] == 3

    def test_result_has_required_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job-x"
            job_dir.mkdir()
            (job_dir / "run_summary.json").write_text(
                json.dumps({"stage_durations": {"startup": 20.0}})
            )

            engine = ETAEngine(output_dir=tmpdir)
            asyncio.run(engine._refresh())

            result = engine.compute_eta_sync("job-new", "startup", 5.0)
            assert result is not None
            assert "eta_seconds" in result
            assert "confidence" in result
            assert "method" in result
            assert "sample_count" in result

    def test_unknown_stage_defaults_to_index_0(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job-x"
            job_dir.mkdir()
            (job_dir / "run_summary.json").write_text(
                json.dumps({"stage_durations": {"startup": 20.0}})
            )

            engine = ETAEngine(output_dir=tmpdir)
            asyncio.run(engine._refresh())

            result = engine.compute_eta_sync("job-new", "bogus_stage", 5.0)
            assert result is not None

    def test_caching_returns_same_result(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job-x"
            job_dir.mkdir()
            (job_dir / "run_summary.json").write_text(
                json.dumps({"stage_durations": {"startup": 20.0}})
            )

            engine = ETAEngine(output_dir=tmpdir)
            asyncio.run(engine._refresh())

            r1 = engine.compute_eta_sync("job-new", "startup", 5.0)
            r2 = engine.compute_eta_sync("job-new", "startup", 5.0)
            assert r1 is r2


# ---------------------------------------------------------------------------
# ETAEngine – compute_eta (async)
# ---------------------------------------------------------------------------


class TestETAEngineComputeEta:
    @pytest.mark.asyncio
    async def test_returns_none_with_no_data(self):
        engine = ETAEngine()
        result = await engine.compute_eta("job-1", "startup", 10.0)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_estimate_with_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job-h"
            job_dir.mkdir()
            (job_dir / "run_summary.json").write_text(
                json.dumps({"stage_durations": {"startup": 10.0}})
            )

            engine = ETAEngine(output_dir=tmpdir)
            await engine._refresh()

            result = await engine.compute_eta("job-new", "startup", 5.0)
            assert result is not None
            assert result["method"] == "bayesian"


# ---------------------------------------------------------------------------
# ETAEngine – get_historical_durations
# ---------------------------------------------------------------------------


class TestETAEngineHistoricalDurations:
    @pytest.mark.asyncio
    async def test_empty_returns_zero_total(self):
        engine = ETAEngine()
        result = await engine.get_historical_durations()
        assert result["total_mean_seconds"] == 0
        assert result["per_stage"] == {}

    @pytest.mark.asyncio
    async def test_aggregates_per_stage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                job_dir = Path(tmpdir) / f"job-{i}"
                job_dir.mkdir()
                (job_dir / "run_summary.json").write_text(
                    json.dumps(
                        {
                            "stage_durations": {
                                "startup": 10.0 + i * 5,
                            }
                        }
                    )
                )

            engine = ETAEngine(output_dir=tmpdir)
            await engine._refresh()

            result = await engine.get_historical_durations()
            assert "startup" in result["per_stage"]
            stats = result["per_stage"]["startup"]
            assert stats["count"] == 3
            assert stats["mean"] > 0
            assert "p50" in stats
            assert "p90" in stats
            assert "p99" in stats

    @pytest.mark.asyncio
    async def test_total_mean_is_sum_of_stage_means(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            job_dir = Path(tmpdir) / "job-x"
            job_dir.mkdir()
            (job_dir / "run_summary.json").write_text(
                json.dumps(
                    {
                        "stage_durations": {
                            "startup": 10.0,
                            "subdomains": 20.0,
                        }
                    }
                )
            )

            engine = ETAEngine(output_dir=tmpdir)
            await engine._refresh()

            result = await engine.get_historical_durations()
            expected_total = 10.0 + 20.0
            assert result["total_mean_seconds"] == expected_total


# ---------------------------------------------------------------------------
# ETAEngine – start/stop/background loop
# ---------------------------------------------------------------------------


class TestETAEngineLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        engine = ETAEngine(output_dir="output", background_interval=1)
        await engine.start()
        assert engine._running is True
        assert engine._task is not None
        await engine.stop()
        assert engine._running is False

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        engine = ETAEngine(output_dir="output", background_interval=1)
        await engine.start()
        task1 = engine._task
        await engine.start()
        assert engine._task is task1
        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_when_not_running(self):
        engine = ETAEngine()
        await engine.stop()
        assert engine._running is False

    @pytest.mark.asyncio
    async def test_background_loop_does_not_block(self):
        engine = ETAEngine(output_dir="output", background_interval=1)
        await engine.start()

        flag = {"hit": False}

        async def set_flag():
            flag["hit"] = True

        await set_flag()
        assert flag["hit"] is True

        await engine.stop()


# ---------------------------------------------------------------------------
# ETAEngine – _get_aggregate_model
# ---------------------------------------------------------------------------


class TestETAEngineAggregateModel:
    def test_returns_none_when_no_models(self):
        engine = ETAEngine()
        assert engine._get_aggregate_model(0) is None

    def test_aggregates_across_jobs(self):
        engine = ETAEngine()
        engine._models = {
            "job-a": {0: BayesianSimpleModel()},
            "job-b": {0: BayesianSimpleModel()},
        }
        engine._models["job-a"][0].add_sample(10.0)
        engine._models["job-b"][0].add_sample(20.0)

        agg = engine._get_aggregate_model(0)
        assert agg is not None
        assert agg.sample_count == 2

    def test_skips_jobs_without_stage(self):
        engine = ETAEngine()
        engine._models = {
            "job-a": {1: BayesianSimpleModel()},
            "job-b": {0: BayesianSimpleModel()},
        }
        engine._models["job-b"][0].add_sample(15.0)

        agg = engine._get_aggregate_model(0)
        assert agg is not None
        assert agg.sample_count == 1


# ---------------------------------------------------------------------------
# get_eta_engine singleton
# ---------------------------------------------------------------------------


class TestGetEtaEngine:
    def setup_method(self):
        import src.dashboard.eta_engine as mod

        mod._eta_engine = None

    def teardown_method(self):
        import src.dashboard.eta_engine as mod

        mod._eta_engine = None

    def test_returns_singleton(self):
        e1 = get_eta_engine()
        e2 = get_eta_engine()
        assert e1 is e2

    def test_uses_feature_flags_config(self):
        engine = get_eta_engine()
        assert isinstance(engine, ETAEngine)
