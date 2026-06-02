import importlib
import sys

modules = [
    "src.infrastructure.execution_engine.concurrent_executor",
    "src.infrastructure.execution_engine._scheduler",
    "src.infrastructure.execution_engine._task_runner",
    "src.infrastructure.cache.cache_manager",
    "src.pipeline.services.pipeline_orchestrator.orchestrator",
]

failed = []
for m in modules:
    try:
        importlib.import_module(m)
    except Exception as e:
        print(f"IMPORT_FAIL {m}: {e}", file=sys.stderr)
        failed.append((m, str(e)))

if failed:
    sys.exit(2)

print("IMPORTS_OK")
