"""CLI entrypoint for background work.

Usage::

    python -m app.jobs.runner scan          # one scan sweep, then exit
    python -m app.jobs.runner refresh-kev   # refresh the KEV catalog, then exit
    python -m app.jobs.runner sweep         # purge expired sessions, then exit
    python -m app.jobs.runner loop          # run the scheduler in the foreground

The one-shot commands exist so the whole background system can be driven by
cron, systemd timers or a platform scheduler instead of a long-lived process —
useful on hosts that stop idle containers. `loop` is the dedicated-worker mode.

Exit code is 0 on success and 1 on failure, so a supervisor can tell.
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys

from app.config import get_settings
from app.db import configure_event_loop_policy, dispose_engine, run_async
from app.jobs.scheduler import build_scheduler
from app.jobs.tasks import (
    backup_task,
    refresh_feeds_task,
    run_scan_cycle,
    sweep_sessions_task,
    sync_mirror_task,
)
from app.logging_config import configure_logging, get_logger

log = get_logger(__name__)


async def _run_once(command: str, limit: int | None) -> int:
    if command == "scan":
        stats = await run_scan_cycle(limit)
        log.info("runner.scan_finished", **stats)
        return 1 if stats["failed"] else 0

    if command == "sync-mirror":
        stats = await sync_mirror_task()
        log.info("runner.mirror_finished", **stats)
        return 1 if stats["failed"] else 0

    if command == "backup":
        stats = await backup_task()
        log.info("runner.backup_finished", **stats)
        return 1 if stats["failed"] else 0

    if command == "refresh-kev":
        count = await refresh_feeds_task()
        log.info("runner.kev_finished", entries=count)
        return 0 if count >= 0 else 1

    if command == "sweep":
        await sweep_sessions_task()
        return 0

    log.error("runner.unknown_command", command=command)
    return 2


async def _run_loop() -> int:
    """Run the scheduler until SIGINT/SIGTERM."""
    settings = get_settings()
    scheduler = build_scheduler(settings)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Windows event loops do not support add_signal_handler; the
            # KeyboardInterrupt path below covers Ctrl+C there.
            pass

    scheduler.start()
    log.info("runner.loop_started")

    # Pull KEV immediately so a cold start is not blind until the first
    # interval. The advisory mirror is deliberately *not* pulled here — it is
    # hundreds of megabytes, and paying that on every worker restart would make
    # deploys slow. The scheduled job covers steady state; `sync-mirror` seeds
    # it explicitly on a fresh deployment.
    await refresh_feeds_task()

    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.shutdown(wait=True)
        log.info("runner.loop_stopped")
    return 0


async def _main_async(args: argparse.Namespace) -> int:
    try:
        if args.command == "loop":
            return await _run_loop()
        return await _run_once(args.command, args.limit)
    finally:
        await dispose_engine()


def main() -> None:
    parser = argparse.ArgumentParser(prog="weedout-scan", description="Weedout background jobs")
    parser.add_argument(
        "command",
        choices=["scan", "sync-mirror", "refresh-kev", "backup", "sweep", "loop"],
        help="scan: one sweep; sync-mirror: pull OSV advisories into the local "
        "mirror; refresh-kev: pull the KEV catalog; backup: dump the database "
        "now; sweep: purge expired sessions; loop: run the scheduler",
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="maximum targets to scan in this sweep"
    )
    args = parser.parse_args()

    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    configure_event_loop_policy()

    try:
        sys.exit(run_async(_main_async(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
