"""Test fixtures.

Integration tests run against a real PostgreSQL database rather than SQLite,
because the schema uses JSONB, filtered aggregates, `ON CONFLICT DO UPDATE` and
advisory locks — none of which SQLite can stand in for. Testing against a
different engine than production would only prove the tests pass.

The database is created once per session and each test runs inside a
transaction that is rolled back, so tests neither see nor leave each other's
data.

Set WEEDOUT_TEST_DATABASE_URL to point at your own Postgres; the default
matches the docker-compose service.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncIterator

import pytest


@pytest.fixture(scope="session")
def event_loop_policy():
    """psycopg's async mode cannot run on Windows' default ProactorEventLoop.

    Mirrors `app.db.configure_event_loop_policy`, which does the same for the
    server. Silenced deprecation: see that function for why.
    """
    if sys.platform != "win32":
        return asyncio.get_event_loop_policy()

    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return asyncio.WindowsSelectorEventLoopPolicy()


# Environment must be set before anything imports app.config, because Settings
# is read once and cached.
_DEFAULT_DSN = "postgresql+psycopg://weedout:weedout@localhost:5435/weedout_test"
TEST_DATABASE_URL = os.environ.get("WEEDOUT_TEST_DATABASE_URL", _DEFAULT_DSN)

os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DEBUG": "false",
        "SECRET_KEY": "test-secret-key-that-is-long-enough-to-pass-validation",
        "DATABASE_URL": TEST_DATABASE_URL,
        "EMAIL_BACKEND": "console",
        "RUN_SCHEDULER_IN_WEB": "false",
        "DODO_ENABLED": "false",
        "LOG_LEVEL": "WARNING",
        "BASE_URL": "http://testserver",
        # ENVIRONMENT=test would otherwise mark cookies Secure, and the test
        # client speaks plain http — so no cookie would ever be sent back.
        "SESSION_COOKIE_SECURE": "false",
    }
)

import httpx  # noqa: E402
import psycopg  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings  # noqa: E402
from app.core.types import Tier  # noqa: E402
from app.db import Base, get_db  # noqa: E402
from app.models import User  # noqa: E402
from app.security import hash_password  # noqa: E402


def _admin_dsn() -> str:
    """A libpq DSN for the `postgres` maintenance database."""
    base = TEST_DATABASE_URL.replace("postgresql+psycopg://", "postgresql://")
    return base.rsplit("/", maxsplit=1)[0] + "/postgres"


def _database_name() -> str:
    return TEST_DATABASE_URL.rsplit("/", maxsplit=1)[-1]


@pytest.fixture(scope="session", autouse=True)
def ensure_test_database() -> None:
    """Create the test database if it does not exist.

    Skips the whole integration suite when Postgres is unreachable, so the pure
    unit tests still run on a machine without Docker.
    """
    name = _database_name()
    try:
        with psycopg.connect(_admin_dsn(), autocommit=True, connect_timeout=5) as conn:
            exists = conn.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s", (name,)
            ).fetchone()
            if not exists:
                conn.execute(f'CREATE DATABASE "{name}"')
    except psycopg.Error as exc:
        pytest.skip(f"PostgreSQL is not reachable for integration tests: {exc}")


@pytest.fixture(scope="session")
async def engine(ensure_test_database):
    """Session-wide engine with the schema created from the ORM metadata.

    `create_all` rather than Alembic: the migration is verified separately by
    `alembic check` in CI, and going through it here would make every test run
    pay for the full migration history.
    """
    eng = create_async_engine(TEST_DATABASE_URL, poolclass=None)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def db(engine) -> AsyncIterator[AsyncSession]:
    """A session bound to a transaction that is rolled back after the test.

    The session joins an outer transaction on a dedicated connection, so even
    code under test that calls `commit()` only commits a savepoint — the outer
    rollback still discards everything.
    """
    connection = await engine.connect()
    transaction = await connection.begin()
    factory = async_sessionmaker(
        bind=connection,
        expire_on_commit=False,
        autoflush=False,
        join_transaction_mode="create_savepoint",
    )
    session = factory()
    try:
        yield session
    finally:
        await session.close()
        await transaction.rollback()
        await connection.close()


@pytest.fixture
async def client(db: AsyncSession) -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client wired to the app, sharing the test's rolled-back session."""
    from app.main import create_app

    app = create_app(get_settings())

    async def override_get_db() -> AsyncIterator[AsyncSession]:
        yield db

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()


@pytest.fixture
async def user(db: AsyncSession) -> User:
    record = User(
        email="dev@example.com",
        password_hash=hash_password("correct-horse-battery"),
        tier=Tier.FREE,
    )
    db.add(record)
    await db.flush()
    return record


@pytest.fixture
async def pro_user(db: AsyncSession) -> User:
    record = User(
        email="pro@example.com",
        password_hash=hash_password("correct-horse-battery"),
        tier=Tier.PRO,
    )
    db.add(record)
    await db.flush()
    return record


def set_csrf(client: httpx.AsyncClient, token: str = "test-csrf-token") -> str:  # noqa: S107
    """Seed the CSRF cookie and return the token to submit alongside it.

    Existing entries are cleared first. The server re-issues this cookie on
    every HTML response, and a manually-set duplicate under a different domain
    key would leave two cookies of the same name in the jar — which makes
    `cookies.get` raise `CookieConflict` and sends an unpredictable pair.
    """
    for cookie in list(client.cookies.jar):
        if cookie.name == "weedout_csrf":
            client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
    client.cookies.set("weedout_csrf", token)
    return token


@pytest.fixture
async def auth_client(client: httpx.AsyncClient, user: User) -> httpx.AsyncClient:
    """A client with a live session cookie for `user`.

    Signs in the way the application does now: a JSON post to the internal API
    with the double-submit CSRF header. The form route this used to call was
    removed when sign-in moved to React, and going through the real endpoint
    keeps this fixture honest — if signing in breaks, every test that needs a
    session fails, which is the correct blast radius.
    """
    csrf = set_csrf(client)
    response = await client.post(
        "/api/internal/auth/login",
        json={"email": user.email, "password": "correct-horse-battery"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200, response.text
    return client


#: The password every fixture account is created with. Named so the shared
#: sign-in helper does not read as a hardcoded credential.
FIXTURE_PASSWORD = "correct-horse-battery"


async def sign_in(client, email: str, password: str = FIXTURE_PASSWORD):
    """Sign a test client in through the real endpoint.

    One helper rather than a copy of the request in every file. Sign-in moved
    from a form post to a JSON post when the screens moved to React, and having
    seventeen copies of the old shape is what made that a seventeen-file edit.

    Returns the response so a caller can assert on a failure it expected.
    """
    csrf = set_csrf(client)
    return await client.post(
        "/api/internal/auth/login",
        json={"email": email, "password": password},
        headers={"X-CSRF-Token": csrf},
    )
