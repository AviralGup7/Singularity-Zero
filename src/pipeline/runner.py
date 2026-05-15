"""Pipeline runner entry point."""

import argparse
import json
from pathlib import Path

from src.pipeline.validation import format_validation_report, validate_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Pipeline Runner")
    parser.add_argument("--config", required=True, help="Path to config JSON")
    parser.add_argument("--scope", required=True, help="Path to scope file")
    parser.add_argument("--refresh-cache", action="store_true")
    parser.add_argument("--force-fresh-run", action="store_true")
    parser.add_argument("--skip-crtsh", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--validate-config",
        action="store_true",
        dest="validate_config",
        help="Validate config and exit without running pipeline",
    )
    args = parser.parse_args()

    # Read config
    config_path = Path(args.config)
    with open(config_path) as f:
        config = json.load(f)

    # Read scope
    scope_path = Path(args.scope)
    with open(scope_path) as f:
        scope_entries = [line.strip() for line in f if line.strip()]

    if args.validate_config:
        output_dir = config.get("output_dir", str(config_path.parent.parent))
        all_ok, report = validate_config(config, scope_entries, output_dir)
        print(format_validation_report(report))
        return 0 if all_ok else 1

    if args.dry_run:
        print("DRY RUN - no execution")
        print(f"Config: {config_path}")
        print(f"Scope entries: {len(scope_entries)}")
        return 0

    output_dir = config.get("output_dir", str(config_path.parent.parent))

    # Import and run the actual pipeline from pipeline_flow
    from src.pipeline.services.pipeline_flow import run_pipeline

    setattr(args, "_loaded_config", config)
    setattr(args, "_loaded_scope_entries", scope_entries)
    run_pipeline(config, scope_entries, output_dir, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
