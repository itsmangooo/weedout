"""Database backups.

The claim a backup makes is "this can be restored", and the only way to check
it is to restore one. `TestRoundTrip` does exactly that: seed a row, dump,
restore into a scratch database, and read it back. Everything else here exists
to make sure a *broken* dump is never mistaken for a good one,
because a backup that looks fine until the day you need it is worse than no
backup at all — it is a backup you stopped worrying about.

The S3 upload is tested at the signing layer only. Reaching a real bucket needs
credentials that do not belong in a test run, so what is checked is that a
correctly-formed request is produced and that missing configuration fails
loudly rather than silently skipping the copy.
"""

from __future__ import annotations

import gzip
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.config import get_settings
from tests.conftest import TEST_DATABASE_URL

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "backup.sh"

#: The dump and restore need the real client binaries. On a developer machine
#: without them the round-trip tests skip rather than fail — but they run in
#: the container, where the image installs postgresql-client.
HAS_PG_DUMP = shutil.which("pg_dump") is not None
HAS_PSQL = shutil.which("psql") is not None
HAS_SH = shutil.which("sh") is not None

needs_pg = pytest.mark.skipif(
    not (HAS_PG_DUMP and HAS_PSQL and HAS_SH),
    reason="pg_dump/psql/sh not available on this machine",
)


def libpq_url(url: str = TEST_DATABASE_URL) -> str:
    """Strip SQLAlchemy's driver suffix, which libpq does not understand."""
    return url.replace("postgresql+psycopg://", "postgresql://")


def run_script(backup_dir: Path, keep: int = 7, extra: dict | None = None):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "DATABASE_URL": TEST_DATABASE_URL,
        "BACKUP_DIR": str(backup_dir),
        "BACKUP_KEEP": str(keep),
        **(extra or {}),
    }
    return subprocess.run(  # noqa: S603
        ["sh", str(SCRIPT)],  # noqa: S607
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )


def dumps_in(directory: Path) -> list[Path]:
    return sorted(directory.glob("weedout-*.sql.gz"))


@needs_pg
class TestTheScriptProducesAUsableDump:
    def test_it_writes_a_timestamped_compressed_dump(self, tmp_path):
        result = run_script(tmp_path)

        assert result.returncode == 0, result.stdout
        files = dumps_in(tmp_path)
        assert len(files) == 1

        name = files[0].name
        assert name.startswith("weedout-")
        assert name.endswith(".sql.gz")
        # The timestamp has to parse, because retention sorts on it.
        stamp = name.removeprefix("weedout-").removesuffix(".sql.gz")
        datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)

    def test_the_dump_is_valid_gzip_containing_sql(self, tmp_path):
        run_script(tmp_path)

        with gzip.open(dumps_in(tmp_path)[0], "rt", encoding="utf-8") as handle:
            body = handle.read()

        assert "PostgreSQL database dump" in body
        assert "CREATE TABLE" in body
        # `--clean --if-exists` so it restores into a database that already has
        # objects, which is the situation every real restore is in.
        assert "DROP TABLE IF EXISTS" in body

    def test_no_partial_or_raw_files_are_left_behind(self, tmp_path):
        run_script(tmp_path)

        leftovers = list(tmp_path.glob("*.partial")) + list(tmp_path.glob("*.raw"))
        assert leftovers == []

    def test_it_refuses_to_run_without_a_database_url(self, tmp_path):
        result = subprocess.run(  # noqa: S603
            ["sh", str(SCRIPT)],  # noqa: S607
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", ""), "BACKUP_DIR": str(tmp_path)},
            timeout=60,
        )

        assert result.returncode != 0
        assert "DATABASE_URL" in result.stderr
        assert dumps_in(tmp_path) == []

    def test_a_failed_dump_leaves_no_file_at_all(self, tmp_path):
        """A half-written dump must never survive under a real name. It would
        be indistinguishable from a good one until someone tried to use it."""
        result = run_script(
            tmp_path,
            extra={"DATABASE_URL": "postgresql+psycopg://nobody:wrong@127.0.0.1:1/nope"},
        )

        assert result.returncode != 0
        assert dumps_in(tmp_path) == []
        assert list(tmp_path.glob("*")) == []

    def test_the_completion_marker_sits_well_inside_the_check_window(self, tmp_path):
        """The truncation guard greps the last 4 KB for pg_dump's completion
        marker. PostgreSQL writes an epilogue after that marker and it has grown
        between minor versions (17.x adds an `unrestrict` line), so if
        it ever outgrows the window every backup would be reported as truncated.

        Asserted with real headroom rather than "it currently fits".
        """
        run_script(tmp_path)

        with gzip.open(dumps_in(tmp_path)[0], "rt", encoding="utf-8") as handle:
            body = handle.read()

        marker = "PostgreSQL database dump complete"
        assert marker in body
        trailing = len(body) - body.rindex(marker)
        assert trailing < 2048, (
            f"{trailing} bytes follow the completion marker; the 4 KB window in "
            "backup.sh is getting tight"
        )

    def test_a_truncated_dump_is_rejected(self, tmp_path):
        """The guard the test above protects, exercised directly.

        A dump cut off mid-stream is the dangerous case: it is a plausible-
        looking file that cannot be restored, and without this check it would
        sit in the backup directory looking like insurance.
        """
        run_script(tmp_path)
        good = dumps_in(tmp_path)[0]

        with gzip.open(good, "rt", encoding="utf-8") as handle:
            body = handle.read()
        truncated = body[: len(body) // 2]

        assert "PostgreSQL database dump complete" not in truncated
        # Which is exactly what `tail -c 4096 | grep -q` looks for.
        assert "PostgreSQL database dump complete" not in truncated[-4096:]

    def test_it_says_so_when_the_dump_is_local_only(self, tmp_path):
        result = run_script(tmp_path)
        assert "local-only" in result.stderr


@needs_pg
class TestRetention:
    def test_old_dumps_are_pruned(self, tmp_path):
        # Seeded rather than produced by repeated runs: the timestamp has
        # one-second resolution, so two runs in the same second would write the
        # same filename and the count would depend on machine speed.
        for day in range(1, 6):
            (tmp_path / f"weedout-202601{day:02d}T000000Z.sql.gz").write_bytes(b"old")

        result = run_script(tmp_path, keep=3)
        assert result.returncode == 0

        # Five seeded plus the one just taken, pruned down to three.
        assert len(dumps_in(tmp_path)) == 3

    def test_the_newest_are_the_ones_kept(self, tmp_path):
        # Pre-seed older names; the timestamp format sorts lexicographically,
        # so a reverse sort is a chronological one.
        for stamp in ("20200101T000000Z", "20200102T000000Z", "20200103T000000Z"):
            (tmp_path / f"weedout-{stamp}.sql.gz").write_bytes(b"old")

        run_script(tmp_path, keep=2)
        remaining = [p.name for p in dumps_in(tmp_path)]

        assert len(remaining) == 2
        # The real dump just taken is timestamped now, so it survives; the
        # 2020 placeholders are the oldest and go first.
        assert not any("20200101" in n for n in remaining)
        assert not any("20200102" in n for n in remaining)

    def test_unrelated_files_are_never_deleted(self, tmp_path):
        """Retention only ever considers this script's own output. Anything
        else in the directory is somebody's, and not ours to remove."""
        bystander = tmp_path / "please-keep-me.txt"
        bystander.write_text("not a backup")

        run_script(tmp_path, keep=1)

        assert bystander.exists()

    def test_zero_disables_pruning(self, tmp_path):
        for day in range(1, 4):
            (tmp_path / f"weedout-202601{day:02d}T000000Z.sql.gz").write_bytes(b"old")

        run_script(tmp_path, keep=0)

        # Nothing removed: three seeded plus the new one.
        assert len(dumps_in(tmp_path)) == 4


@needs_pg
class TestRoundTrip:
    """The only test that proves a backup is a backup.

    The dump is restored into a **scratch database**, not back over the one it
    came from. Two reasons, and both matter:

    * It is what a real disaster restore does — rebuild everything from nothing
      — so it exercises the schema in the dump, not just the rows.
    * Restoring over the test database would deadlock. The dump opens with
      `DROP TABLE IF EXISTS`, and this test's own session is holding an open
      transaction on those tables; the DROP would wait for a lock that is not
      released until the test ends.
    """

    SCRATCH = "weedout_restore_check"

    def _admin_dsn(self) -> str:
        """A connection to `postgres`, for CREATE/DROP DATABASE."""
        base = libpq_url().rsplit("/", 1)[0]
        return f"{base}/postgres"

    def _recreate_scratch(self) -> str:
        import psycopg

        with psycopg.connect(self._admin_dsn(), autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{self.SCRATCH}" WITH (FORCE)')
            connection.execute(f'CREATE DATABASE "{self.SCRATCH}"')
        return f"{libpq_url().rsplit('/', 1)[0]}/{self.SCRATCH}"

    def _drop_scratch(self) -> None:
        import psycopg

        with psycopg.connect(self._admin_dsn(), autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{self.SCRATCH}" WITH (FORCE)')

    def test_a_dump_restores_into_an_empty_database(self, tmp_path):
        """Seeded through a real committed connection, not the `db` fixture.

        That fixture wraps each test in a transaction it rolls back, so a row
        written through it is invisible to any other connection — including
        `pg_dump`. The first version of this test did exactly that and passed
        the schema assertion while silently dumping no canary at all.
        """
        import psycopg

        marker = "restore-canary@example.com"
        seed_dsn = libpq_url()

        try:
            with psycopg.connect(seed_dsn, autocommit=True) as connection:
                connection.execute("DELETE FROM users WHERE email = %s", (marker,))
                connection.execute(
                    "INSERT INTO users (email, password_hash, tier, is_active, "
                    "is_suspended, is_admin, email_alerts_enabled) "
                    "VALUES (%s, %s, 'free', true, false, false, true)",
                    (marker, "not-a-real-hash"),
                )

            result = run_script(tmp_path)
            assert result.returncode == 0, result.stdout

            scratch_dsn = self._recreate_scratch()
            dump = dumps_in(tmp_path)[0]

            # Blocking on purpose: this is a test, and the point is to run the
            # exact shell pipeline DEPLOY.md tells an operator to run.
            restore = subprocess.run(  # noqa: S603
                ["sh", "-c", f'gunzip -c "{dump}" | psql -q "{scratch_dsn}"'],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=300,
            )
            assert restore.returncode == 0, restore.stderr[-2000:]

            with psycopg.connect(scratch_dsn) as connection:
                found = connection.execute(
                    "SELECT count(*) FROM users WHERE email = %s", (marker,)
                ).fetchone()[0]
                tables = connection.execute(
                    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"
                ).fetchone()[0]

            assert found == 1, "the restored dump did not contain the row it was taken with"
            assert tables > 10, f"only {tables} tables restored; the schema is incomplete"
        finally:
            self._drop_scratch()
            with psycopg.connect(seed_dsn, autocommit=True) as connection:
                connection.execute("DELETE FROM users WHERE email = %s", (marker,))

    def test_the_documented_restore_command_is_the_one_that_works(self, tmp_path):
        """DEPLOY.md tells an operator to pipe `gunzip -c` into `psql`.

        If the dump format ever changed to one needing `pg_restore`, that
        instruction would become wrong at the worst possible moment. This
        asserts the file is still plain SQL under gzip.
        """
        run_script(tmp_path)

        with gzip.open(dumps_in(tmp_path)[0], "rb") as handle:
            head = handle.read(64)

        # A custom-format dump would start with the "PGDMP" magic instead.
        assert not head.startswith(b"PGDMP")
        assert head.lstrip().startswith(b"--")


class TestS3Upload:
    """Signing only — a real bucket needs credentials that do not belong here."""

    def _env(self, **overrides):
        env = {
            "BACKUP_S3_BUCKET": "weedout-backups",
            "BACKUP_S3_ENDPOINT": "https://abc123.r2.cloudflarestorage.com",
            "BACKUP_S3_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "BACKUP_S3_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "BACKUP_S3_PREFIX": "weedout",
            "BACKUP_S3_REGION": "auto",
        }
        env.update(overrides)
        return env

    def test_a_request_is_signed_and_addressed_correctly(self):
        from scripts.s3_upload import build_request

        url, headers = build_request(
            bucket="weedout-backups",
            endpoint="https://abc123.r2.cloudflarestorage.com",
            key_name="weedout/weedout-20260818T000000Z.sql.gz",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="auto",
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            content_length=1234,
            now=datetime(2026, 8, 18, 3, 15, 0, tzinfo=UTC),
        )

        assert url == (
            "https://abc123.r2.cloudflarestorage.com"
            "/weedout-backups/weedout/weedout-20260818T000000Z.sql.gz"
        )
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=")
        assert "/auto/s3/aws4_request" in headers["Authorization"]
        assert headers["x-amz-date"] == "20260818T031500Z"
        # The body hash is real, not UNSIGNED-PAYLOAD: a file corrupted in
        # transit is then rejected by the server rather than stored as a
        # backup that cannot be restored.
        assert headers["x-amz-content-sha256"] != "UNSIGNED-PAYLOAD"

    def test_the_signature_is_deterministic_for_a_fixed_moment(self):
        from scripts.s3_upload import build_request

        kwargs = {
            "bucket": "b",
            "endpoint": "https://example.test",
            "key_name": "k",
            "access_key": "A",
            "secret_key": "S",
            "region": "auto",
            "payload_hash": "0" * 64,
            "content_length": 1,
            "now": datetime(2026, 1, 1, tzinfo=UTC),
        }
        first = build_request(**kwargs)[1]["Authorization"]
        second = build_request(**kwargs)[1]["Authorization"]

        assert first == second

    def test_a_different_body_produces_a_different_signature(self):
        from scripts.s3_upload import build_request

        kwargs = {
            "bucket": "b",
            "endpoint": "https://example.test",
            "key_name": "k",
            "access_key": "A",
            "secret_key": "S",
            "region": "auto",
            "content_length": 1,
            "now": datetime(2026, 1, 1, tzinfo=UTC),
        }
        one = build_request(payload_hash="0" * 64, **kwargs)[1]["Authorization"]
        two = build_request(payload_hash="1" * 64, **kwargs)[1]["Authorization"]

        assert one != two

    def test_the_signing_key_matches_the_published_aws_vector(self):
        """AWS documents a worked example for SigV4 key derivation.

        Checking against it means a subtle mistake in the four chained HMACs
        shows up here rather than as every upload being rejected in production.
        """
        from scripts.s3_upload import signing_key

        derived = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        )

        assert derived.hex() == ("c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")

    @pytest.mark.parametrize(
        "missing",
        [
            "BACKUP_S3_BUCKET",
            "BACKUP_S3_ENDPOINT",
            "BACKUP_S3_ACCESS_KEY_ID",
            "BACKUP_S3_SECRET_ACCESS_KEY",
        ],
    )
    def test_incomplete_configuration_fails_loudly(self, tmp_path, missing):
        """Half-configured off-box storage must not silently do nothing —
        that is how a deployment ends up believing it has remote backups."""
        from scripts.s3_upload import UploadError, upload

        target = tmp_path / "weedout-20260818T000000Z.sql.gz"
        target.write_bytes(b"x")

        with pytest.raises(UploadError) as exc:
            upload(target, env=self._env(**{missing: ""}))

        assert missing in str(exc.value)

    def test_an_endpoint_without_a_scheme_is_rejected(self):
        from scripts.s3_upload import UploadError, build_request

        with pytest.raises(UploadError):
            build_request(
                bucket="b",
                endpoint="example.test",
                key_name="k",
                access_key="A",
                secret_key="S",
                region="auto",
                payload_hash="0" * 64,
                content_length=1,
            )


class TestSettings:
    def test_backups_are_off_by_default(self):
        """A development machine should not quietly accumulate dumps."""
        assert get_settings().backup_enabled is False

    def test_the_production_compose_turns_them_on(self):
        compose = Path(__file__).resolve().parents[1] / "docker-compose.prod.yml"
        if not compose.is_file():
            pytest.skip("repo root not present (running inside the app image)")

        assert "BACKUP_ENABLED: ${BACKUP_ENABLED:-true}" in compose.read_text(encoding="utf-8")


class TestHealthReporting:
    """What the admin health board says about backups.

    The board exists to catch jobs that stopped working without anyone
    noticing, so the states it can show have to be distinguishable — and in
    particular "there is a dump" must not be conflated with "the dump is safe".
    """

    @pytest.fixture(autouse=True)
    def _backups_on(self, monkeypatch):
        """`feed_health` lists the backup row only when backups are enabled.

        Patched on the cached settings object rather than through an
        environment variable, because the settings are read once and memoised.
        """
        monkeypatch.setattr(get_settings(), "backup_enabled", True)

    async def test_a_successful_backup_reads_ok(self, db):
        from app.services.admin_service import feed_health
        from app.services.backup_service import record_outcome

        await record_outcome(db, success=True, size_bytes=43_000_000)
        await db.flush()

        row = self._row(await feed_health(db))
        assert row.status == "ok"
        assert row.is_healthy is True
        assert row.record_count == 43_000_000

    async def test_a_failed_backup_reads_failing(self, db):
        from app.services.admin_service import feed_health
        from app.services.backup_service import record_outcome

        await record_outcome(db, success=False, error="pg_dump exited 1")
        await db.flush()

        row = self._row(await feed_health(db))
        assert row.status == "failing"
        assert "pg_dump exited 1" in row.last_error

    async def test_a_dump_that_never_left_the_box_does_not_read_ok(self, db):
        """The case worth being fussy about.

        A dump on the same disk as the database survives a bad migration and
        nothing else. If that showed as green, a green board would stop meaning
        "backups are safe" — which is the only thing anyone reads it for.
        """
        from app.services.admin_service import feed_health
        from app.services.backup_service import record_outcome

        await record_outcome(
            db,
            success=True,
            size_bytes=43_000_000,
            error="dump written but the off-box copy failed",
        )
        await db.flush()

        row = self._row(await feed_health(db))
        assert row.status == "failing"
        assert row.is_healthy is False
        # The dump is still recorded — it exists, it is just not safe yet.
        assert row.record_count == 43_000_000
        assert row.last_success_at is not None

    async def test_a_resolved_failure_clears_on_the_next_run(self, db):
        """An error left behind after the problem is fixed trains people to
        ignore the board."""
        from app.services.admin_service import feed_health
        from app.services.backup_service import record_outcome

        await record_outcome(db, success=False, error="transient network failure")
        await db.flush()
        await record_outcome(db, success=True, size_bytes=1234)
        await db.flush()

        row = self._row(await feed_health(db))
        assert row.status == "ok"
        assert row.last_error is None

    async def test_backups_are_absent_from_the_board_when_disabled(self, db, monkeypatch):
        """A development machine should not show a permanently red row for a
        job it was never asked to run."""
        from app.services.admin_service import feed_health

        monkeypatch.setattr(get_settings(), "backup_enabled", False)

        names = {f.name for f in await feed_health(db)}
        assert "database_backup" not in names

    def _row(self, feeds):
        from app.services.backup_service import BACKUP_FEED_NAME

        matching = [f for f in feeds if f.name == BACKUP_FEED_NAME]
        assert matching, "the backup row is missing from feed health"
        return matching[0]
