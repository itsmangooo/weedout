"""Server-sent events: the figures that change while you are looking at them.

SSE rather than WebSockets because the traffic is one-directional — the server
has news, the browser has nothing to say back — and SSE is a plain HTTP
response. That means it survives the existing `connect-src 'self'` policy with
no change, reconnects on its own with no client code, and needs no protocol
upgrade through whatever proxy sits in front of this.

Nothing here is load-bearing. Every figure it pushes is already rendered into
the page by the handler that served it; this only keeps them current. With the
stream blocked, buffered or unsupported, the page is exactly the page it was.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.core.types import AlertStatus, Verdict
from app.db import session_scope
from app.deps import CurrentUser
from app.logging_config import get_logger
from app.models import CVEMatch, TrackedTarget

log = get_logger(__name__)

router = APIRouter(tags=["events"])

#: How often the server looks for something new. These are counts on an indexed
#: column for one user; the cost is small and the latency budget for "a scan
#: finished" is seconds, not milliseconds.
POLL_SECONDS = 5

#: Sent when nothing has changed, to keep intermediaries from closing an idle
#: connection. A comment line is valid SSE and fires no client-side event.
HEARTBEAT_SECONDS = 25


async def _snapshot(user_id: int) -> dict[str, int]:
    """The live figures for one account.

    Opens its own session per tick rather than holding the request's open for
    the life of the stream — a connection parked for an hour is a connection
    the pool cannot give to anyone else.
    """
    async with session_scope() as db:
        row = (
            await db.execute(
                select(
                    func.count(CVEMatch.id).filter(
                        CVEMatch.verdict == Verdict.ACTIONABLE,
                        CVEMatch.status == AlertStatus.OPEN,
                    ),
                    func.count(CVEMatch.id).filter(
                        CVEMatch.is_kev.is_(True),
                        CVEMatch.status == AlertStatus.OPEN,
                    ),
                    func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
                )
                .select_from(CVEMatch)
                .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
                .where(TrackedTarget.user_id == user_id)
            )
        ).one()

    return {"open": row[0], "exploited": row[1], "filtered": row[2]}


def _format(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


@router.get("/events")
async def events(request: Request, user: CurrentUser) -> StreamingResponse:
    """A stream of this user's own figures.

    Scoped to `user` by the same dependency every other page uses, so a stream
    can only ever carry the account that opened it.
    """

    async def stream() -> AsyncIterator[str]:
        previous: dict[str, int] | None = None
        idle = 0.0

        # The first frame is sent immediately: it both primes the client and
        # confirms the stream is genuinely open, which is what the live dot
        # reports.
        try:
            while True:
                if await request.is_disconnected():
                    break

                try:
                    current = await _snapshot(user.id)
                except Exception as exc:
                    log.warning("events.snapshot_failed", error=str(exc))
                    await asyncio.sleep(POLL_SECONDS)
                    continue

                if current != previous:
                    payload = dict(current)
                    if previous is not None and current["open"] > previous["open"]:
                        new = current["open"] - previous["open"]
                        payload["_banner"] = (
                            f"{new} new {'finding' if new == 1 else 'findings'} since you "
                            "opened this page."
                        )
                    yield _format("stats", payload)
                    previous = current
                    idle = 0.0
                elif idle >= HEARTBEAT_SECONDS:
                    yield ": keep-alive\n\n"
                    idle = 0.0

                await asyncio.sleep(POLL_SECONDS)
                idle += POLL_SECONDS
        except asyncio.CancelledError:
            # The client went away mid-sleep. Normal, not an error.
            raise

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            # nginx buffers proxied responses by default, which turns a live
            # stream into one long silence followed by everything at once.
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
