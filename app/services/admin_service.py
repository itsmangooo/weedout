"""Administrative queries and mutations.

Kept in its own module — like `app/routes/admin.py` — so that "what can an
administrator do?" is answerable by reading two files rather than grepping the
codebase for privilege checks.

Every mutation here writes an `AdminAuditLog` row in the same transaction as the
change it describes. That coupling is deliberate: an audit trail written on a
separate path can silently drift from reality, and a trail that is missing
exactly the entries you need is worse than none because it looks complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.types import AlertStatus, Tier, Verdict
from app.logging_config import get_logger
from app.models import (
    AdminAuditLog,
    Alert,
    CVEMatch,
    FeedSync,
    ScanRun,
    TrackedTarget,
    User,
    utcnow,
)

log = get_logger(__name__)

__all__ = [
    "AdminActionError",
    "FeedHealth",
    "PlatformMetrics",
    "RevenueSnapshot",
    "UserPage",
    "change_user_tier",
    "delete_user",
    "is_last_admin",
    "list_users",
    "platform_metrics",
    "record_audit",
    "suspend_user",
    "unsuspend_user",
]

#: Feed identifiers tracked in the `feed_syncs` table. The advisory mirror
#: registers one row per ecosystem — see `mirror_feed_name`.
KEV_FEED_NAME = "cisa_kev"


class AdminActionError(Exception):
    """An administrative action was rejected for a stated reason."""


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def record_audit(
    db: AsyncSession,
    actor: User,
    action: str,
    target: User | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> AdminAuditLog:
    """Append an audit entry. Caller commits alongside the change it describes."""
    entry = AdminAuditLog(
        actor_user_id=actor.id,
        actor_email=actor.email,
        action=action,
        target_user_id=target.id if target else None,
        target_email=target.email if target else None,
        details=details or {},
        ip_address=(ip_address or "")[:64] or None,
    )
    db.add(entry)
    log.info(
        "admin.action",
        action=action,
        actor_id=actor.id,
        target_id=target.id if target else None,
        **{k: v for k, v in (details or {}).items() if isinstance(v, str | int | bool | None)},
    )
    return entry


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class UserRow:
    """One row of the user list, with its counts already resolved."""

    user: User
    target_count: int = 0
    open_alert_count: int = 0


@dataclass(slots=True)
class UserPage:
    rows: list[UserRow] = field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 25

    @property
    def pages(self) -> int:
        if self.per_page <= 0:
            return 1
        return max(1, -(-self.total // self.per_page))  # ceiling division

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    @property
    def start_index(self) -> int:
        return 0 if self.total == 0 else (self.page - 1) * self.per_page + 1

    @property
    def end_index(self) -> int:
        return min(self.page * self.per_page, self.total)


def _apply_user_filters(
    query: Select, search: str | None, tier: Tier | None, status: str | None
) -> Select:
    """Filters shared by the page query and its count query.

    Sharing them is what keeps the pagination total honest — a count computed
    over different predicates than the rows produces a page count that does not
    match the data.
    """
    if search:
        # Escape LIKE wildcards so a user searching for "a_b" does not get
        # every address with any character between "a" and "b".
        escaped = search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        query = query.where(User.email.ilike(f"%{escaped}%", escape="\\"))

    if tier is not None:
        query = query.where(User.tier == tier)

    if status == "suspended":
        query = query.where(User.is_suspended.is_(True))
    elif status == "active":
        query = query.where(User.is_suspended.is_(False), User.is_active.is_(True))
    elif status == "admin":
        query = query.where(User.is_admin.is_(True))

    return query


async def list_users(
    db: AsyncSession,
    page: int = 1,
    per_page: int = 25,
    search: str | None = None,
    tier: Tier | None = None,
    status: str | None = None,
) -> UserPage:
    """A page of users with their target and open-alert counts.

    Counts come from two grouped queries over just the users on this page,
    rather than a correlated subquery per row or a lazy load in the template —
    both of which turn a 25-row page into 50 round trips.
    """
    total = (
        await db.scalar(
            _apply_user_filters(select(func.count(User.id)).select_from(User), search, tier, status)
        )
    ) or 0

    query = _apply_user_filters(select(User), search, tier, status)
    users = list(
        (
            await db.scalars(
                query.order_by(User.created_at.desc(), User.id.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
            )
        ).all()
    )

    if not users:
        return UserPage(rows=[], total=total, page=page, per_page=per_page)

    user_ids = [u.id for u in users]

    target_counts = dict(
        (
            await db.execute(
                select(TrackedTarget.user_id, func.count(TrackedTarget.id))
                .where(TrackedTarget.user_id.in_(user_ids))
                .group_by(TrackedTarget.user_id)
            )
        ).all()
    )

    alert_counts = dict(
        (
            await db.execute(
                select(TrackedTarget.user_id, func.count(CVEMatch.id))
                .join(CVEMatch, CVEMatch.target_id == TrackedTarget.id)
                .where(
                    TrackedTarget.user_id.in_(user_ids),
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                )
                .group_by(TrackedTarget.user_id)
            )
        ).all()
    )

    return UserPage(
        rows=[
            UserRow(
                user=user,
                target_count=target_counts.get(user.id, 0),
                open_alert_count=alert_counts.get(user.id, 0),
            )
            for user in users
        ],
        total=total,
        page=page,
        per_page=per_page,
    )


@dataclass(slots=True)
class UserDetail:
    user: User
    targets: list[TrackedTarget] = field(default_factory=list)
    recent_alerts: list[Alert] = field(default_factory=list)
    audit_entries: list[AdminAuditLog] = field(default_factory=list)
    open_alert_count: int = 0
    suppressed_count: int = 0
    scan_count: int = 0


async def user_detail(db: AsyncSession, user_id: int) -> UserDetail | None:
    """Everything the per-user admin view shows."""
    user = await db.get(User, user_id)
    if user is None:
        return None

    targets = list(
        (
            await db.scalars(
                select(TrackedTarget)
                .where(TrackedTarget.user_id == user_id)
                .order_by(TrackedTarget.created_at.desc())
            )
        ).all()
    )

    recent_alerts = list(
        (
            await db.scalars(
                select(Alert)
                .where(Alert.user_id == user_id)
                .order_by(Alert.created_at.desc())
                .limit(20)
            )
        ).all()
    )

    audit_entries = list(
        (
            await db.scalars(
                select(AdminAuditLog)
                .where(AdminAuditLog.target_user_id == user_id)
                .order_by(AdminAuditLog.created_at.desc())
                .limit(20)
            )
        ).all()
    )

    counts = (
        await db.execute(
            select(
                func.count(CVEMatch.id).filter(
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                ),
                func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
            )
            .select_from(CVEMatch)
            .join(TrackedTarget, TrackedTarget.id == CVEMatch.target_id)
            .where(TrackedTarget.user_id == user_id)
        )
    ).one()

    scan_count = (
        await db.scalar(
            select(func.count(ScanRun.id))
            .join(TrackedTarget, TrackedTarget.id == ScanRun.target_id)
            .where(TrackedTarget.user_id == user_id)
        )
    ) or 0

    return UserDetail(
        user=user,
        targets=targets,
        recent_alerts=recent_alerts,
        audit_entries=audit_entries,
        open_alert_count=counts[0] or 0,
        suppressed_count=counts[1] or 0,
        scan_count=scan_count,
    )


async def change_user_tier(
    db: AsyncSession,
    actor: User,
    target: User,
    new_tier: Tier,
    note: str = "",
    ip_address: str | None = None,
) -> None:
    """Set a user's tier by hand — for comps, support credits and refunds.

    Deliberately does **not** touch the Dodo subscription fields. Those are
    owned by the webhook, and overwriting them here would make the billing view
    disagree with Dodo's own records. A manual tier is an override layered on
    top, and the audit entry records that it was manual so a later billing
    discrepancy is explicable.
    """
    if target.tier is new_tier:
        raise AdminActionError(f"{target.email} is already on the {new_tier.value} plan.")

    previous = target.tier
    target.tier = new_tier

    record_audit(
        db,
        actor,
        action="user.tier_changed",
        target=target,
        details={
            "from": previous.value,
            "to": new_tier.value,
            "note": note,
            "manual_override": True,
            "dodo_subscription_id": target.dodo_subscription_id,
        },
        ip_address=ip_address,
    )


async def suspend_user(
    db: AsyncSession,
    actor: User,
    target: User,
    reason: str = "",
    ip_address: str | None = None,
) -> None:
    """Suspend an account. Reversible, and destroys nothing.

    Suspension blocks sign-in, invalidates live sessions on their next request
    (`User.can_sign_in` is consulted per request), and removes the account's
    targets from the scan queue. Manifests, findings and history all remain, so
    `unsuspend_user` restores the account exactly as it was.
    """
    if target.id == actor.id:
        raise AdminActionError(
            "You can't suspend your own account — that would lock you out of this panel."
        )
    if target.is_admin:
        raise AdminActionError("Administrator accounts can't be suspended.")
    if target.is_suspended:
        raise AdminActionError(f"{target.email} is already suspended.")

    target.is_suspended = True
    target.suspended_at = utcnow()
    target.suspension_reason = (reason or "").strip()[:500] or None

    record_audit(
        db,
        actor,
        action="user.suspended",
        target=target,
        details={"reason": target.suspension_reason or ""},
        ip_address=ip_address,
    )


async def is_last_admin(db: AsyncSession, user: User) -> bool:
    """Is this the only account that can still reach the admin panel?

    The single source of truth for that question — the web delete path and
    `python -m app.manage demote-admin` both consult it, so the two can never
    disagree about whether an action would lock everyone out.
    """
    if not user.is_admin:
        return False
    other = await db.scalar(
        select(User.id).where(User.is_admin.is_(True), User.id != user.id).limit(1)
    )
    return other is None


async def delete_user(
    db: AsyncSession,
    actor: User,
    target: User,
    ip_address: str | None = None,
) -> dict[str, int]:
    """Permanently delete an account and everything belonging to it.

    Unlike suspension, this is irreversible. Tracked targets, dependencies,
    findings, scan history and alert records all go with the account, by
    `ON DELETE CASCADE` at the database level rather than by an application
    loop — so nothing is orphaned if this is ever run outside the ORM.

    The audit entry is written *first*, and deliberately retains `target_email`
    as a plain column. `AdminAuditLog.target_user_id` is `ON DELETE SET NULL`,
    so the row survives the deletion with the address still readable: an audit
    trail that loses the identity of the thing it describes records nothing
    worth having.

    Returns what was removed, which is also recorded in the trail.
    """
    if target.id == actor.id:
        raise AdminActionError(
            "You can't delete your own account from here — that would remove the "
            "only way back into this panel."
        )
    if await is_last_admin(db, target):
        raise AdminActionError(
            "That's the only administrator account. Promote a replacement before "
            "deleting it, or nobody can reach this panel."
        )

    counts = (
        await db.execute(
            select(
                func.count(TrackedTarget.id.distinct()),
                func.count(CVEMatch.id.distinct()),
            )
            .select_from(TrackedTarget)
            .outerjoin(CVEMatch, CVEMatch.target_id == TrackedTarget.id)
            .where(TrackedTarget.user_id == target.id)
        )
    ).one()

    alert_count = (
        await db.scalar(select(func.count(Alert.id)).where(Alert.user_id == target.id))
    ) or 0

    removed = {
        "targets": counts[0] or 0,
        "matches": counts[1] or 0,
        "alerts": alert_count,
    }

    record_audit(
        db,
        actor,
        action="user.deleted",
        target=target,
        details={
            "email": target.email,
            "tier": target.tier.value,
            "was_suspended": target.is_suspended,
            "dodo_subscription_id": target.dodo_subscription_id,
            "removed": removed,
        },
        ip_address=ip_address,
    )
    # Flushed before the delete so the entry exists to be SET NULL, rather than
    # being inserted afterwards against a user id that no longer resolves.
    await db.flush()

    await db.delete(target)
    await db.flush()

    log.warning(
        "admin.user_deleted",
        actor_id=actor.id,
        deleted_email=target.email,
        **removed,
    )
    return removed


async def unsuspend_user(
    db: AsyncSession, actor: User, target: User, ip_address: str | None = None
) -> None:
    """Lift a suspension and put the account's targets back in the scan queue."""
    if not target.is_suspended:
        raise AdminActionError(f"{target.email} is not suspended.")

    previous_reason = target.suspension_reason
    target.is_suspended = False
    target.suspended_at = None
    target.suspension_reason = None

    record_audit(
        db,
        actor,
        action="user.unsuspended",
        target=target,
        details={"previous_reason": previous_reason or ""},
        ip_address=ip_address,
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class FeedHealth:
    """Sync state of one upstream feed.

    Surfaced prominently because a silently broken feed breaks the product's
    core promise without breaking any page: scans keep running, the dashboard
    keeps rendering, and the alerts are quietly wrong.
    """

    name: str
    label: str
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None
    last_error: str | None = None
    record_count: int = 0
    catalog_version: str | None = None
    #: Hours after which this feed is considered stale.
    stale_after_hours: int = 24

    @property
    def is_healthy(self) -> bool:
        return self.last_success_at is not None and not self.is_stale and not self.last_error

    @property
    def is_stale(self) -> bool:
        if self.last_success_at is None:
            return True
        return utcnow() - self.last_success_at > timedelta(hours=self.stale_after_hours)

    @property
    def status(self) -> str:
        """The most actionable true statement about this feed.

        A recorded error wins over "never synced": a feed that has been tried
        and broke on every attempt since deployment is *failing*, and reporting
        it as merely never-synced reads like "not set up yet" — which sends the
        reader looking at configuration instead of at the error.
        """
        if self.last_error:
            return "failing"
        if self.last_success_at is None:
            return "never synced"
        if self.is_stale:
            return "stale"
        return "ok"


async def feed_health(db: AsyncSession) -> list[FeedHealth]:
    """Sync state for every feed the product depends on.

    Each mirrored ecosystem is listed separately rather than rolled into one
    "OSV" line. A single aggregate row would read green while, say, the Go
    export had been failing for a week — and every Go user would be told they
    are clean. The `record_count` column is what makes an export that starts
    returning near-nothing visible; a feed can succeed and still be broken.
    """
    from app.services.mirror_service import MIRRORED_ECOSYSTEMS, mirror_feed_name

    rows = {row.name: row for row in (await db.scalars(select(FeedSync))).all()}

    definitions = [(KEV_FEED_NAME, "CISA KEV", 24)]
    definitions += [
        (
            mirror_feed_name(ecosystem),
            f"OSV advisories — {ecosystem}",
            get_settings().mirror_stale_after_hours,
        )
        for ecosystem in MIRRORED_ECOSYSTEMS
    ]

    health: list[FeedHealth] = []
    for name, label, stale_hours in definitions:
        row = rows.get(name)
        health.append(
            FeedHealth(
                name=name,
                label=label,
                last_success_at=row.last_success_at if row else None,
                last_attempt_at=row.last_attempt_at if row else None,
                last_error=row.last_error if row else None,
                record_count=row.record_count if row else 0,
                catalog_version=row.catalog_version if row else None,
                stale_after_hours=stale_hours,
            )
        )
    return health


@dataclass(slots=True)
class PlatformMetrics:
    total_users: int = 0
    free_users: int = 0
    paid_users: int = 0
    suspended_users: int = 0
    new_users_7d: int = 0

    total_targets: int = 0
    total_dependencies: int = 0

    scans_today: int = 0
    scans_7d: int = 0
    scans_all_time: int = 0
    failed_scans_7d: int = 0

    open_alerts: int = 0
    suppressed_alerts: int = 0
    alerts_emailed_7d: int = 0

    @property
    def paid_share(self) -> int:
        """Conversion, as a whole percentage."""
        if self.total_users == 0:
            return 0
        return round(self.paid_users / self.total_users * 100)

    @property
    def noise_filtered_share(self) -> int:
        """Share of real matches the filter suppressed, across every account.

        The product's headline claim, measured over all users rather than one.
        """
        total = self.open_alerts + self.suppressed_alerts
        if total == 0:
            return 0
        return round(self.suppressed_alerts / total * 100)


async def platform_metrics(db: AsyncSession) -> PlatformMetrics:
    """Headline counts, in four grouped queries rather than a dozen."""
    now = utcnow()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    user_row = (
        await db.execute(
            select(
                func.count(User.id),
                func.count(User.id).filter(User.tier == Tier.FREE),
                func.count(User.id).filter(User.tier == Tier.PRO),
                func.count(User.id).filter(User.is_suspended.is_(True)),
                func.count(User.id).filter(User.created_at >= week_ago),
            )
        )
    ).one()

    target_row = (
        await db.execute(
            select(
                func.count(TrackedTarget.id),
                func.coalesce(func.sum(TrackedTarget.dependency_count), 0),
            )
        )
    ).one()

    scan_row = (
        await db.execute(
            select(
                func.count(ScanRun.id).filter(ScanRun.started_at >= day_ago),
                func.count(ScanRun.id).filter(ScanRun.started_at >= week_ago),
                func.count(ScanRun.id),
                func.count(ScanRun.id).filter(
                    ScanRun.started_at >= week_ago, ScanRun.status == "failed"
                ),
            )
        )
    ).one()

    match_row = (
        await db.execute(
            select(
                func.count(CVEMatch.id).filter(
                    CVEMatch.verdict == Verdict.ACTIONABLE,
                    CVEMatch.status == AlertStatus.OPEN,
                ),
                func.count(CVEMatch.id).filter(CVEMatch.verdict == Verdict.SUPPRESSED),
            )
        )
    ).one()

    emailed = (
        await db.scalar(
            select(func.count(Alert.id)).where(Alert.created_at >= week_ago, Alert.status == "sent")
        )
    ) or 0

    return PlatformMetrics(
        total_users=user_row[0] or 0,
        free_users=user_row[1] or 0,
        paid_users=user_row[2] or 0,
        suspended_users=user_row[3] or 0,
        new_users_7d=user_row[4] or 0,
        total_targets=target_row[0] or 0,
        total_dependencies=target_row[1] or 0,
        scans_today=scan_row[0] or 0,
        scans_7d=scan_row[1] or 0,
        scans_all_time=scan_row[2] or 0,
        failed_scans_7d=scan_row[3] or 0,
        open_alerts=match_row[0] or 0,
        suppressed_alerts=match_row[1] or 0,
        alerts_emailed_7d=emailed,
    )


@dataclass(slots=True)
class SignupPoint:
    day: date
    count: int
    cumulative: int


async def signups_over_time(db: AsyncSession, days: int = 30) -> list[SignupPoint]:
    """Daily signup counts for the last `days` days.

    Days with no signups are filled in with zero rather than omitted — a line
    chart that skips empty days compresses quiet periods and overstates the
    trend. The running total is computed here so the template does no
    arithmetic.
    """
    since = (utcnow() - timedelta(days=days - 1)).date()

    rows = (
        await db.execute(
            select(
                func.date(User.created_at).label("day"),
                func.count(User.id),
            )
            .where(func.date(User.created_at) >= since)
            .group_by(func.date(User.created_at))
            .order_by(func.date(User.created_at))
        )
    ).all()

    counts: dict[date, int] = {}
    for row_day, row_count in rows:
        # Postgres `date()` returns a date; be tolerant of a driver returning str.
        key = row_day if isinstance(row_day, date) else date.fromisoformat(str(row_day))
        counts[key] = row_count

    # Everything before the window still counts toward the cumulative line.
    baseline = (
        await db.scalar(select(func.count(User.id)).where(func.date(User.created_at) < since))
    ) or 0

    points: list[SignupPoint] = []
    running = baseline
    for offset in range(days):
        day = since + timedelta(days=offset)
        count = counts.get(day, 0)
        running += count
        points.append(SignupPoint(day=day, count=count, cumulative=running))

    return points


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------

#: Provider statuses in which money is expected to keep arriving.
#: `on_hold` is Dodo's dunning state — the bank is still retrying, so the
#: revenue is not lost yet and the customer keeps access.
PAYING_STATUSES = ("active", "trialing", "on_hold")

#: Statuses that have stopped producing revenue.
ENDED_STATUSES = ("cancelled", "canceled", "expired", "failed", "paused")


@dataclass(slots=True)
class RevenueSnapshot:
    active_count: int = 0
    #: Dunning: payment failed, retries in progress, access retained.
    past_due_count: int = 0
    canceled_count: int = 0
    trialing_count: int = 0
    mrr_cents: int = 0
    currency: str = "USD"
    #: Paid accounts with no recorded subscription — comps, or a webhook that
    #: arrived before the amount fields existed. Surfaced rather than hidden,
    #: because a silent gap here understates revenue.
    untracked_paid_count: int = 0

    @property
    def mrr(self) -> float:
        return self.mrr_cents / 100

    @property
    def arr(self) -> float:
        return self.mrr * 12


async def revenue_snapshot(db: AsyncSession) -> RevenueSnapshot:
    """At-a-glance revenue. Computed from what the webhooks already stored.

    Deliberately not a call to Dodo's API: this page is checked often, and it
    should not break or hang because Dodo is slow. Anything needing authority
    — refunds, disputes, invoice corrections — links out to Dodo instead.
    """
    rows = list(
        (await db.scalars(select(User).where(User.dodo_subscription_id.is_not(None)))).all()
    )

    snapshot = RevenueSnapshot()
    currencies: dict[str, int] = {}

    for user in rows:
        status = (user.subscription_status or "").lower()
        if status == "active":
            snapshot.active_count += 1
        elif status == "trialing":
            snapshot.trialing_count += 1
        elif status == "on_hold":
            snapshot.past_due_count += 1
        elif status in ENDED_STATUSES:
            snapshot.canceled_count += 1

        if status in PAYING_STATUSES:
            snapshot.mrr_cents += user.monthly_value_cents
            if user.subscription_currency:
                currencies[user.subscription_currency] = (
                    currencies.get(user.subscription_currency, 0) + 1
                )

    if currencies:
        snapshot.currency = max(currencies, key=lambda c: currencies[c])

    snapshot.untracked_paid_count = (
        await db.scalar(
            select(func.count(User.id)).where(
                User.tier == Tier.PRO,
                or_(
                    User.dodo_subscription_id.is_(None),
                    User.subscription_amount_cents.is_(None),
                ),
            )
        )
    ) or 0

    return snapshot


async def list_subscribers(db: AsyncSession, limit: int = 200) -> list[User]:
    """Everyone with a Dodo subscription, paying ones first."""
    return list(
        (
            await db.scalars(
                select(User)
                .where(User.dodo_subscription_id.is_not(None))
                .order_by(
                    User.subscription_status.notin_(PAYING_STATUSES),
                    User.subscription_ends_at.asc().nulls_last(),
                )
                .limit(limit)
            )
        ).all()
    )


async def recent_audit_entries(db: AsyncSession, limit: int = 100) -> list[AdminAuditLog]:
    return list(
        (
            await db.scalars(
                select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()).limit(limit)
            )
        ).all()
    )
