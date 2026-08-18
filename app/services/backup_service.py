"""Scheduled database backups.

The dump itself is `scripts/backup.sh` rather than Python: `pg_dump` is the
tool for this, and shelling out to it means the scheduled backup and the one an
operator runs by hand before a risky migration are byte-for-byte the same
procedure. A reimplementation in Python would be a second procedure that is
only exercised on the schedule, and therefore the one that quietly breaks.

Outcomes are recorded on a `FeedSync` row. That table is named for the feeds it
was built for, but its shape — name, last attempt, last success, last error,
a count — is exactly "state of a recurring job", and reusing it puts backups on
the admin panel's health board next to the advisory feeds. A backup that
stopped working three weeks ago is precisely the kind of silent failure that
board exists to catch.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.logging_config import get_logger
from app.models import FeedSync, utcnow

log = get_logger(__name__)

__all__ = [
    "BACKUP_FEED_NAME",
    "BackupError",
    "BackupResult",
    "latest_backup",
    "run_backup",
]

#: `FeedSync.name` for the backup job.
BACKUP_FEED_NAME = "database_backup"

#: The script is part of the image, resolved relative to this file so it works
#: whether the app runs from /app in a container or from a checkout.
SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "backup.sh"


class BackupError(RuntimeError):
    """The backup did not produce a usable dump."""


@dataclass(slots=True)
class BackupResult:
    path: Path | None
    size_bytes: int
    uploaded: bool
    output: str


def _environment(settings: Settings) -> dict[str, str]:
    """The environment the script runs with.

    Built explicitly rather than inherited wholesale so that what the script
    can see is a short, readable list — and so a credential that has no
    business in a subprocess is not handed to one by default.
    """
    import os

    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "DATABASE_URL": str(settings.database_url),
        "BACKUP_DIR": settings.backup_dir,
        "BACKUP_KEEP": str(settings.backup_keep),
        "BACKUP_S3_PREFIX": settings.backup_s3_prefix,
        "BACKUP_S3_REGION": settings.backup_s3_region,
    }
    if settings.backup_s3_bucket:
        env["BACKUP_S3_BUCKET"] = settings.backup_s3_bucket
        env["BACKUP_S3_ENDPOINT"] = settings.backup_s3_endpoint or ""
        env["BACKUP_S3_ACCESS_KEY_ID"] = settings.backup_s3_access_key_id or ""
        env["BACKUP_S3_SECRET_ACCESS_KEY"] = settings.backup_s3_secret_access_key or ""
    return env


async def run_backup(settings: Settings | None = None) -> BackupResult:
    """Run one backup. Raises `BackupError` if no usable dump was produced.

    An off-box upload failure is *not* fatal: the local dump is real and
    keeping it beats discarding it. The result says whether the copy left the
    box so the caller can be loud about it separately.
    """
    settings = settings or get_settings()

    if not SCRIPT_PATH.is_file():
        raise BackupError(f"backup script missing at {SCRIPT_PATH}")
    if shutil.which("pg_dump") is None:
        raise BackupError("pg_dump is not installed in this image")

    process = await asyncio.create_subprocess_exec(
        "sh",
        str(SCRIPT_PATH),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_environment(settings),
    )

    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=settings.backup_timeout_seconds
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        raise BackupError(f"backup timed out after {settings.backup_timeout_seconds}s") from None

    output = (stdout or b"").decode("utf-8", "replace").strip()

    # 0 = everything worked. 1 = the dump is good but the off-box copy failed;
    # the script keeps the local file in that case, so it is a warning rather
    # than a lost backup. Anything else means no usable dump.
    if process.returncode not in (0, 1):
        raise BackupError(f"backup script failed (exit {process.returncode}): {output[-500:]}")

    newest = latest_backup(settings)
    if newest is None:
        raise BackupError(f"backup script reported success but wrote nothing: {output[-500:]}")

    uploaded = bool(settings.backup_s3_bucket) and process.returncode == 0
    return BackupResult(
        path=newest,
        size_bytes=newest.stat().st_size,
        uploaded=uploaded,
        output=output,
    )


def latest_backup(settings: Settings | None = None) -> Path | None:
    """The newest local dump, or None. Named so the timestamp orders them."""
    settings = settings or get_settings()
    directory = Path(settings.backup_dir)
    if not directory.is_dir():
        return None
    dumps = sorted(directory.glob("weedout-*.sql.gz"))
    return dumps[-1] if dumps else None


async def record_outcome(
    db: AsyncSession,
    *,
    success: bool,
    size_bytes: int = 0,
    error: str | None = None,
) -> None:
    """Write the result where the admin panel will show it.

    `success` and `error` are independent, which is not an oversight. A dump can
    be written successfully and still fail to leave the machine, and that
    combination has to be visible: a backup sitting on the same disk as the
    database does not protect against the failure it exists for. Passing both
    records the dump *and* leaves the health row reading "failing", so nobody
    concludes from a green board that off-box copies are working.

    Never raises. Failing to record a backup must not also fail the backup —
    but a job whose bookkeeping has silently stopped is a job nobody is
    watching, so it is logged.
    """
    try:
        sync = await db.get(FeedSync, BACKUP_FEED_NAME)
        if sync is None:
            sync = FeedSync(name=BACKUP_FEED_NAME)
            db.add(sync)

        sync.last_attempt_at = utcnow()
        if success:
            sync.last_success_at = utcnow()
            # Bytes rather than rows: for a backup, "it produced 40 bytes" is
            # the signal that something is wrong, and a count of rows would not
            # show it.
            sync.record_count = size_bytes

        # Set unconditionally so a resolved problem clears the row on the next
        # run rather than showing an error that no longer applies.
        sync.last_error = (error or "unknown error")[:2000] if error or not success else None
    except Exception as exc:
        log.warning("backup.record_failed", error=str(exc))


def backup_stale_after(settings: Settings | None = None) -> timedelta:
    """How old a successful backup may be before the panel calls it stale.

    Twice the interval plus an hour: one missed run is a blip worth noticing
    on the next pass, two is a pattern.
    """
    settings = settings or get_settings()
    return timedelta(hours=settings.backup_interval_hours * 2 + 1)
