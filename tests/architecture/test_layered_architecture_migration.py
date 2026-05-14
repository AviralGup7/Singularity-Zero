import unittest
from pathlib import Path

from src.core.config import load_config as core_load_config
from src.pipeline.storage import load_config


class LayeredArchitectureMigrationTests(unittest.TestCase):
    def test_storage_load_config_uses_core_loader(self) -> None:
        config_path = Path("configs/config.example.json")
        storage_cfg = load_config(config_path)
        core_cfg = core_load_config(config_path)
        self.assertEqual(storage_cfg.target_name, core_cfg.target_name)
        self.assertEqual(storage_cfg.output_dir, core_cfg.output_dir)

    def test_layer_packages_import(self) -> None:
        import src.analysis as analysis
        import src.execution.validators as validation
        import src.recon as recon
        import src.reporting as reporting
        from src.dashboard.fastapi.main import main as dashboard_main
        from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

        self.assertTrue(hasattr(recon, "collect_urls"))
        self.assertTrue(hasattr(analysis, "ANALYSIS_PLUGIN_SPECS"))
        self.assertTrue(hasattr(validation, "execute_validation_runtime"))
        self.assertTrue(hasattr(reporting, "build_summary"))
        self.assertTrue(callable(PipelineOrchestrator))
        self.assertTrue(callable(dashboard_main))
        self.assertTrue(hasattr(analysis, "ANALYSIS_PLUGIN_SPECS_BY_KEY"))


if __name__ == "__main__":
    unittest.main()
