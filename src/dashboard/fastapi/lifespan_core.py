"""Phase 1: Core infrastructure startup — logging, secrets, plugins, cache, services."""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def startup_core(app: FastAPI, config: Any) -> None:
    """Core infrastructure — logging, secrets, plugins, cache, services."""
    from src.core.logging.trace_logging import install_trace_log_filter
    from src.core.plugins.loader import (
        refresh_dynamic_plugins,
        start_dynamic_plugin_watcher,
    )
    from src.dashboard.fastapi.collaboration import TriageCollaborationService
    from src.dashboard.fastapi.process_lock import ProcessLifespanLock
    from src.dashboard.fastapi.routers.cache import start_cache_analytics
    from src.dashboard.services import DashboardServices
    from src.infrastructure.cache import CacheManager
    from src.infrastructure.cache.config import CacheConfig
    from src.infrastructure.observability.metrics import get_metrics, register_pipeline_metrics
    from src.infrastructure.observability.structured_logging import setup_logging
    from src.infrastructure.observability.system_sampler import start_system_sampler
    from src.infrastructure.security.audit import AuditLogger
    from src.infrastructure.security.config import SecurityConfig

    setup_logging()
    install_trace_log_filter()
    register_pipeline_metrics(get_metrics())
    start_system_sampler()

    logger.info("Dashboard server starting on %s:%d", config.host, config.port)
    logger.info("Project Root: %s", config.workspace_root)
    logger.info("Frontend Dist: %s", config.frontend_dist)

    from src.core.security.secret_validator import validate_or_raise

    validate_or_raise()

    optional_api_keys = {
        "VIRUSTOTAL_API_KEY": "VirusTotal",
        "SHODAN_API_KEY": "Shodan",
        "ALIENVAULT_API_KEY": "AlienVault",
        "CVE_API_KEY": "CVE",
    }
    unconfigured = [name for name, _ in optional_api_keys.items() if not os.getenv(name)]
    if unconfigured:
        logger.info(
            "Optional API integrations not configured (feature disabled): %s",
            ", ".join(unconfigured),
        )

    refresh_dynamic_plugins()
    start_dynamic_plugin_watcher()

    app.state.audit_logger = AuditLogger(SecurityConfig())

    cache_config = CacheConfig(
        sqlite_db_path=config.cache_db_path,
        cache_dir=config.cache_dir,
        redis_url=config.redis_url,
    )
    app.state.cache_manager = CacheManager(config=cache_config)
    app.state.cache_analytics_task = start_cache_analytics(app)

    app.state.services = DashboardServices(
        workspace_root=config.workspace_root,
        output_root=config.output_root,
        config_template=config.config_template,
    )
    app.state.services.cache_manager = app.state.cache_manager

    lock_path = config.output_root / "startup.lock"
    app.state.lifespan_lock = ProcessLifespanLock(str(lock_path))
    is_primary = app.state.lifespan_lock.acquire()

    db_path = config.output_root / "jobs.db"
    app.state.services.init_persistence(db_path, is_primary=is_primary)
    app.state.triage_collaboration = TriageCollaborationService(config.output_root)

    from src.learning.collaboration import get_default_store

    assignment_db_path = config.output_root / "assignments.db"
    app.state.assignment_store = get_default_store(db_path=str(assignment_db_path))
    logger.info("Assignment store initialized at %s", assignment_db_path)
