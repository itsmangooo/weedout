"""Database engine, session factory and the declarative base.

One async engine per process, created lazily so that importing `app.db` does not
require a reachable database (Alembic and the test suite both rely on that).
"""

from __future__ import annotations

import asyncio
import sys
import warnings
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import Enum as SAEnum
from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

# Explicit, deterministic constraint names. Without these, Alembic autogenerate
# produces unnamed constraints that cannot be dropped in a downgrade.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def enum_column(enum_cls: type, name: str) -> SAEnum:
    """Persist a `StrEnum` as a CHECK-constrained VARCHAR.

    Native PostgreSQL enum types require a migration to add a single value,
    which is a poor trade for a young schema. `values_callable` is required so
    that the enum's *value* is stored rather than its Python member name —
    `Ecosystem.PYPI` must round-trip as ``"PyPI"``, the identifier OSV uses.
    """
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        length=64,
        validate_strings=True,
        values_callable=lambda enum: [member.value for member in enum],
    )


def configure_event_loop_policy() -> None:
    """On Windows, make the selector event loop the process default.

    psycopg's async mode cannot run on `ProactorEventLoop`, which is Python's
    default on Windows. A no-op on Linux, so this affects local development
    only; the production container runs on Linux where the default is fine.

    This is best-effort belt-and-braces. It is *not* sufficient on its own,
    because libraries that create their own loop can and do reset the policy
    first — uvicorn installs the proactor policy when it is not running a
    reload supervisor, which silently undoes this. Anything that owns its
    entrypoint should call `run_async` instead, which cannot be overridden.

    `set_event_loop_policy` is deprecated as of Python 3.14; the warning is
    silenced rather than left to surface on every boot.
    """
    if sys.platform != "win32":
        return

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def run_async(coro: Any) -> Any:
    """`asyncio.run` with an event loop psycopg can actually use.

    Passing `loop_factory` pins the loop for this run directly, rather than
    asking the global policy and hoping nothing else has changed it. That
    distinction matters: the policy approach fails in exactly the configuration
    that is hardest to notice — a non-reload server on Windows, where uvicorn
    resets the policy after we set it and the first database query is what
    tells you.
    """
    if sys.platform == "win32":
        return asyncio.run(coro, loop_factory=asyncio.SelectorEventLoop)
    return asyncio.run(coro)


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            str(settings.database_url),
            echo=settings.db_echo,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,  # survives Postgres restarts and idle-connection reaping
            pool_recycle=1800,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,  # attributes stay readable after commit
            autoflush=False,
        )
    return _session_factory


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a session bound to the request.

    The session is rolled back and closed no matter how the request ends, so a
    failed handler can never leak an open transaction back into the pool.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional scope for background jobs and CLI entrypoints."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def dispose_engine() -> None:
    """Close all pooled connections. Called on application shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


def reset_engine_for_testing(**engine_kwargs: Any) -> None:
    """Point the module at a fresh engine. Test fixtures only."""
    global _engine, _session_factory
    _engine = create_async_engine(str(get_settings().database_url), **engine_kwargs)
    _session_factory = async_sessionmaker(bind=_engine, expire_on_commit=False, autoflush=False)
