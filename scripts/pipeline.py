"""Pipeline entry point - runs analysis pipeline."""

import os
import sys
import traceback

try:
    from src.pipeline.runtime import main
except Exception as exc:
    # Print to stderr so the dashboard can capture it
    print(f"FATAL: Failed to import pipeline runtime: {exc}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FATAL: Pipeline crashed: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
