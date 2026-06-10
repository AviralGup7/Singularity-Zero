import asyncio
import logging
import os
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger(__name__)

try:
    from src.core.models.pipeline_state import Base

    target_metadata = Base.metadata
except Exception:
    target_metadata = None
    logger.warning("Could not load model metadata; autogenerate disabled. Run migrations manually.")


def get_url() -> str:
    url = os.getenv("DATABASE_URL")
    if url:
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url
    url = config.get_main_option("sqlalchemy.url")
    if url is None:
        raise RuntimeError(
            "DATABASE_URL environment variable or sqlalchemy.url config is required. "
            "Alembic must not silently default to SQLite for migrations."
        )
    if os.getenv("APP_ENV") == "production" and url and "sqlite" in url:
        raise RuntimeError("DATABASE_URL is required in production; sqlite fallback is unsafe.")
    return url


def verify_schema_versions() -> None:
    try:
        from sqlalchemy import text

        url = get_url()
        if url.startswith("postgresql+asyncpg://") or url.startswith("postgresql://"):
            import asyncio

            from sqlalchemy.ext.asyncio import create_async_engine

            async def _verify() -> None:
                engine = create_async_engine(url)
                async with engine.connect() as conn:
                    result = await conn.execute(
                        text(
                            "SELECT version_num FROM alembic_version ORDER BY version_num DESC LIMIT 1"
                        )
                    )
                    row = result.fetchone()
                    current = row[0] if row else None
                    logger.info("Current alembic_version: %s", current)
                await engine.dispose()

            asyncio.run(_verify())
        else:
            from sqlalchemy import create_engine

            engine = create_engine(url)
            with engine.connect() as conn:
                result = conn.execute(
                    text(
                        "SELECT version_num FROM alembic_version ORDER BY version_num DESC LIMIT 1"
                    )
                )
                row = result.fetchone()
                current = row[0] if row else None
                logger.info("Current alembic_version: %s", current)
    except Exception as exc:
        logger.warning("Schema version verification skipped: %s", exc)


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Any) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
