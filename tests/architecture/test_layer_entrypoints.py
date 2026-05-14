import unittest


class LayerEntrypointTests(unittest.TestCase):
    def test_pipeline_entrypoint_imports_layered_runtime(self) -> None:
        import src.pipeline as pipeline

        self.assertTrue(callable(pipeline.main))  # type: ignore[attr-defined]

    def test_dashboard_entrypoint_imports_layered_ui(self) -> None:
        import src.dashboard as dashboard

        self.assertTrue(callable(dashboard.main))  # type: ignore[attr-defined]

    def test_legacy_runner_still_exports_main(self) -> None:
        from src.pipeline.runtime import main

        self.assertTrue(callable(main))


if __name__ == "__main__":
    unittest.main()
