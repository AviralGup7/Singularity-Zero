import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ------------------------------------------------------------------
# Model metadata for autogenerate support
# ------------------------------------------------------------------
# When SQLAlchemy models are defined, import their Base.metadata here:
#   from src.core.models import Base
#   target_metadata = Base.metadata
#
# Until then, migrations must be written manually.
# ------------------------------------------------------------------
target_metadata = None


def get_url() -> str:
    """Get database URL from config or environment variable."""
    url = os.getenv("DATABASE_URL")
    if url:
        # Convert postgresql:// to postgresql+asyncpg:// for async
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
    return url


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""
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
    """Run migrations with the given connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in online mode with async engine."""
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
    """Run migrations in online mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
