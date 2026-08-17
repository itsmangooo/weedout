"""Alembic environment.

The database URL comes from application settings rather than alembic.ini, so
there is exactly one place credentials are configured and no risk of a
connection string being committed.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Importing the models module registers every table on Base.metadata.
# Without this import, autogenerate would see an empty schema and helpfully
# offer to drop the entire database.
import app.models  # noqa: F401
from app.config import get_settings
from app.db import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().sync_database_url)

target_metadata = Base.metadata


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Skip objects Alembic should not manage."""
    if type_ == "table" and name in {"alembic_version"}:
        return False
    return True


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting — for reviewing a migration."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Catch column type and default drift, not just added/removed columns.
            compare_type=True,
            compare_server_default=True,
            include_object=include_object,
            # Wrap each migration in its own transaction so a failure rolls back
            # cleanly instead of leaving a half-applied schema.
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
