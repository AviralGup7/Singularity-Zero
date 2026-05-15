"""Console entrypoint shim for the dashboard server.

Ensures repository root is available on sys.path so imports using the
``src.*`` package prefix work when launched via installed console scripts.
"""

import os
import sys
from pathlib import Path


def _ensure_repo_root_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    os.chdir(repo_root_str)


def main(argv: list[str] | None = None) -> None:
    _ensure_repo_root_on_path()
    from src.dashboard.fastapi.main import main as dashboard_main

    dashboard_main(argv)


if __name__ == "__main__":
    main()
