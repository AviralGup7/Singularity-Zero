"""Heavy instrumentation for pipeline startup debugging.

This script patches key functions in the pipeline startup path to log
entry/exit/blocking behavior. Run it as:

    python -m src.pipeline.instrument_startup --config <config> --scope <scope> --force-fresh-run

Or replace the runtime entry point temporarily.
"""

import argparse
import asyncio
import functools
import logging
import sys
import time

# ---------------------------------------------------------------------------
# Instrumentation logging setup
# ---------------------------------------------------------------------------
instrument_logger = logging.getLogger("pipeline.instrument")
instrument_logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
instrument_logger.addHandler(handler)


def log_enter(func_name):
    instrument_logger.debug("ENTER %s", func_name)


def log_exit(func_name, **kwargs):
    details = " ".join(f"{k}={v}" for k, v in kwargs.items())
    instrument_logger.debug("EXIT %s %s", func_name, details)


def log_block(func_name, reason):
    instrument_logger.warning("BLOCK %s: %s", func_name, reason)


def instrument(cls, method_name, prefix=None):
    """Patch a method on a class to log entry/exit."""
    prefix = prefix or method_name
    original = getattr(cls, method_name)

    @functools.wraps(original)
    def wrapper(*args, **kwargs):
        log_enter(prefix)
        start = time.time()
        try:
            result = original(*args, **kwargs)
        except Exception as exc:
            log_block(prefix, f"exception={exc}")
            raise
        elapsed = time.time() - start
        if asyncio.iscoroutine(result) or asyncio.isfuture(result):
            # Async function returned a coroutine/future
            log_block(prefix, f"returned async object (elapsed={elapsed:.3f}s)")
            # We cannot wrap the coroutine here easily without changing callers,
            # so just note it.
        else:
            log_exit(prefix, elapsed=f"{elapsed:.3f}s", type=type(result).__name__)
        return result

    setattr(cls, method_name, wrapper)


# ---------------------------------------------------------------------------
# Patch key classes and functions
# ---------------------------------------------------------------------------


def _apply_instrumentation():
    """Apply instrumentation patches to key pipeline components."""
    instrument_logger.info("Applying startup instrumentation patches...")

    # 1. PipelineOrchestrator.run
    from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

    instrument(PipelineOrchestrator, "run", prefix="PipelineOrchestrator.run")
    instrument(PipelineOrchestrator, "_run_secured", prefix="PipelineOrchestrator._run_secured")
    instrument(
        PipelineOrchestrator,
        "_acquire_distributed_lock",
        prefix="PipelineOrchestrator._acquire_distributed_lock",
    )

    # 2. bootstrap_pipeline
    from src.pipeline.services.pipeline_orchestrator._orchestrator.bootstrap import (
        bootstrap_pipeline,
    )

    original_bootstrap = bootstrap_pipeline

    @functools.wraps(original_bootstrap)
    def wrapped_bootstrap(args):
        log_enter("bootstrap_pipeline")
        start = time.time()
        try:
            result = original_bootstrap(args)
            log_exit(
                "bootstrap_pipeline",
                elapsed=f"{time.time() - start:.3f}s",
                result_type=type(result).__name__,
            )
            return result
        except Exception as exc:
            log_block("bootstrap_pipeline", f"exception={exc}")
            raise

    # Monkey-patch the module
    import src.pipeline.services.pipeline_orchestrator._orchestrator.bootstrap as bootstrap_mod

    bootstrap_mod.bootstrap_pipeline = wrapped_bootstrap

    # 3. run_secured
    from src.pipeline.services.pipeline_orchestrator._orchestrator.security import run_secured

    original_run_secured = run_secured

    @functools.wraps(original_run_secured)
    async def wrapped_run_secured(*args, **kwargs):
        log_enter("run_secured")
        start = time.time()
        try:
            result = await original_run_secured(*args, **kwargs)
            log_exit("run_secured", elapsed=f"{time.time() - start:.3f}s", result=result)
            return result
        except Exception as exc:
            log_block("run_secured", f"exception={exc}")
            raise

    import src.pipeline.services.pipeline_orchestrator._orchestrator.security as security_mod

    security_mod.run_secured = wrapped_run_secured

    # 4. execute_remaining_stages
    from src.pipeline.services.pipeline_orchestrator._run_execution import execute_remaining_stages

    original_exec = execute_remaining_stages

    @functools.wraps(original_exec)
    async def wrapped_execute(*args, **kwargs):
        log_enter("execute_remaining_stages")
        start = time.time()
        try:
            result = await original_exec(*args, **kwargs)
            log_exit(
                "execute_remaining_stages", elapsed=f"{time.time() - start:.3f}s", result=result
            )
            return result
        except Exception as exc:
            log_block("execute_remaining_stages", f"exception={exc}")
            raise

    import src.pipeline.services.pipeline_orchestrator._run_execution as exec_mod

    exec_mod.execute_remaining_stages = wrapped_execute

    # 5. ActorScheduler.run
    from src.pipeline.services.pipeline_orchestrator.actor_scheduler import ActorScheduler

    instrument(ActorScheduler, "run", prefix="ActorScheduler.run")
    instrument(ActorScheduler, "_collect_ready_nodes", prefix="ActorScheduler._collect_ready_nodes")
    instrument(ActorScheduler, "_dispatch", prefix="ActorScheduler._dispatch")
    instrument(
        ActorScheduler, "_await_any_completion", prefix="ActorScheduler._await_any_completion"
    )
    instrument(ActorScheduler, "_condition_holds", prefix="ActorScheduler._condition_holds")
    instrument(ActorScheduler, "_deps_satisfied", prefix="ActorScheduler._deps_satisfied")

    # 6. build_pipeline_graph
    from src.pipeline.services.pipeline_orchestrator.graph_builder import build_pipeline_graph

    original_build = build_pipeline_graph

    @functools.wraps(original_build)
    def wrapped_build(*args, **kwargs):
        log_enter("build_pipeline_graph")
        start = time.time()
        try:
            result = original_build(*args, **kwargs)
            log_exit(
                "build_pipeline_graph",
                elapsed=f"{time.time() - start:.3f}s",
                nodes=len(result.nodes) if hasattr(result, "nodes") else "?",
            )
            return result
        except Exception as exc:
            log_block("build_pipeline_graph", f"exception={exc}")
            raise

    import src.pipeline.services.pipeline_orchestrator.graph_builder as gb_mod

    gb_mod.build_pipeline_graph = wrapped_build

    # 7. StagePlanner.plan_stages
    try:
        from src.pipeline.services.pipeline_orchestrator.stage_planner import StagePlanner

        instrument(StagePlanner, "plan_stages", prefix="StagePlanner.plan_stages")
    except ImportError:
        pass

    # 8. CacheManager init
    from src.infrastructure.cache.cache_manager import CacheManager

    instrument(CacheManager, "__init__", prefix="CacheManager.__init__")

    # 9. attempt_recovery
    from src.core.checkpoint import attempt_recovery

    original_attempt = attempt_recovery

    @functools.wraps(original_attempt)
    def wrapped_attempt(*args, **kwargs):
        log_enter("attempt_recovery")
        start = time.time()
        try:
            result = original_attempt(*args, **kwargs)
            log_exit("attempt_recovery", elapsed=f"{time.time() - start:.3f}s", result=result)
            return result
        except Exception as exc:
            log_block("attempt_recovery", f"exception={exc}")
            raise

    import src.core.checkpoint as cp_mod

    cp_mod.attempt_recovery = wrapped_attempt

    instrument_logger.info("Instrumentation patches applied.")


# ---------------------------------------------------------------------------
# Run the instrumented pipeline
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Instrumented pipeline runtime")
    parser.add_argument("--config", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--force-fresh-run", action="store_true")
    args = parser.parse_args()

    _apply_instrumentation()

    from src.pipeline.runtime import main as runtime_main

    log_enter("runtime_main")
    start = time.time()
    try:
        exit_code = runtime_main(
            [
                "--config",
                args.config,
                "--scope",
                args.scope,
            ]
            + (["--force-fresh-run"] if args.force_fresh_run else [])
        )
        log_exit("runtime_main", elapsed=f"{time.time() - start:.3f}s", exit_code=exit_code)
        sys.exit(exit_code)
    except Exception as exc:
        log_block("runtime_main", f"exception={exc}")
        raise


if __name__ == "__main__":
    main()
