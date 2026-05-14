import importlib
import sys

modules = [
    "src.pipeline.services.pipeline_orchestrator.__init__",
    "src.pipeline.services.pipeline_orchestrator.orchestrator",
    "src.analysis.intelligence.findings.intelligence_findings.specs.semgrep",
    "src.pipeline.services.pipeline_orchestrator.stages.__init__",
    "src.pipeline.services.pipeline_orchestrator.stages.semgrep",
    "src.dashboard.fastapi.routers.__init__",
    "src.dashboard.fastapi.routers.imports",
]

failed = 0
for m in modules:
    try:
        importlib.import_module(m)
        print(f"OK: {m}")
    except Exception as e:
        print(f"ERR: {m} -> {e!r}")
        failed += 1

if failed:
    sys.exit(2)
print("IMPORT CHECK: all modules imported successfully")
