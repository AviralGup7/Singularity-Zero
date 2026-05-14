"""Entry point for the FastAPI dashboard server.

Replaces dashboard_app.server:main as the primary entry point.

Usage:
    python -m fastapi_dashboard.main
    uvicorn fastapi_dashboard.main:app --host 127.0.0.1 --port 8080
"""

import argparse
import logging
import sys
from pathlib import Path

from src.dashboard.fastapi.app import create_app
from src.dashboard.fastapi.config import DashboardConfig
from src.infrastructure.security.encryption import TLSConfig

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the dashboard server."""
    parser = argparse.ArgumentParser(description="Cyber Security Test Pipeline Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8000, help="Bind port")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument(
        "--directory",
        default="",
        help="Output directory (deprecated, use --output-root instead)",
    )
    parser.add_argument(
        "--output-root",
        default="",
        help="Root directory for scan output",
    )
    parser.add_argument(
        "--config-template",
        default="",
        help="Path to config template JSON file",
    )
    parser.add_argument("--mtls", action="store_true", help="Require client certificates")
    parser.add_argument("--tls-certfile", default="", help="Server TLS certificate path")
    parser.add_argument("--tls-keyfile", default="", help="Server TLS private key path")
    parser.add_argument("--tls-ca-certs", default="", help="CA bundle for client certificates")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Run the FastAPI dashboard server using uvicorn."""
    args = parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    directory = args.directory or ""
    if not directory:
        directory = str(Path(__file__).resolve().parent.parent / "output")

    output_root = Path(args.output_root) if args.output_root else Path(directory)
    config_template = (
        Path(args.config_template) if args.config_template else output_root / "config_template.json"
    )

    config = DashboardConfig(
        host=args.host,
        port=args.port,
        output_root=output_root,
        config_template=config_template,
        mtls_enabled=args.mtls,
        tls_certfile=args.tls_certfile or None,
        tls_keyfile=args.tls_keyfile or None,
        tls_ca_certs=args.tls_ca_certs or None,
    )

    app = create_app(config)
    uvicorn_ssl_kwargs = {}
    if config.mtls_enabled:
        if not (config.tls_certfile and config.tls_keyfile and config.tls_ca_certs):
            logger.error("--mtls requires --tls-certfile, --tls-keyfile, and --tls-ca-certs")
            sys.exit(2)
        uvicorn_ssl_kwargs = TLSConfig().get_uvicorn_mtls_kwargs(
            certfile=config.tls_certfile,
            keyfile=config.tls_keyfile,
            ca_certs=config.tls_ca_certs,
        )

    try:
        import uvicorn

        uvicorn.run(
            app,
            host=config.host,
            port=config.port,
            log_level=args.log_level.lower(),
            workers=args.workers,
            reload=args.reload,
            **uvicorn_ssl_kwargs,
        )
    except ImportError:
        logger.error("uvicorn is required to run the dashboard server.")
        logger.error("Install it with: pip install uvicorn")
        sys.exit(1)


if __name__ == "__main__":
    main()
