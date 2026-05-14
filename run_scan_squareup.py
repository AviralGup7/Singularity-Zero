import asyncio
import os
import sys

sys.path.insert(0, os.getcwd())

from pathlib import Path

from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator


async def main() -> None:
    print("=" * 60)
    print("SQUARE.COM / SQUAREUP.COM / SQUARE.ONLINE PIPELINE SCAN")
    print("=" * 60)

    # Create output directory
    output_dir = Path("src/dashboard/output/squareup")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Config and scope paths
    config_path = Path("src/dashboard/config/squareup.json")
    scope_path = output_dir / "scope.txt"

    # Create scope file if it doesn't exist
    if not scope_path.exists():
        with open(scope_path, "w", encoding="utf-8") as f:
            f.write("*.square.com\n*.squareup.com\n*.square.online\n")

    if config_path.exists():
        print(f"\nConfig loaded from {config_path}")
    else:
        print(f"Config not found at {config_path}. Falling back to default.")

    # Create orchestrator
    orchestrator = PipelineOrchestrator()

    # Run the pipeline
    print("\n" + "=" * 60)
    print("STARTING PIPELINE SCAN")
    print("Target: squareup.com")
    print("Scope: *.square.com, *.squareup.com, *.square.online")
    print("=" * 60)

    import argparse
    args = argparse.Namespace(
        config=str(config_path) if config_path.exists() else "configs/config.json",
        scope=str(scope_path),
        dry_run=False,
    )

    exit_code = await orchestrator.run(args)

    print("\n" + "=" * 60)
    print(f"SCAN COMPLETE (Exit Code: {exit_code})")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
