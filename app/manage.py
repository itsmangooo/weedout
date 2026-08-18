"""Operator CLI: ``python -m app.manage <command>``.

Commands that need a human decision and should never be reachable from the web
UI. Chiefly admin bootstrap — there is no "become admin" page precisely because
privilege escalation should require shell access to the host, not a browser.

    python -m app.manage ensure-admin
    python -m app.manage promote-admin you@example.com
    python -m app.manage demote-admin  you@example.com
    python -m app.manage list-admins
    python -m app.manage reseed-docs [--force]
    python -m app.manage test-email you@example.com
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from app.config import get_settings
from app.db import configure_event_loop_policy, dispose_engine, run_async, session_scope
from app.logging_config import configure_logging, get_logger
from app.models import AdminAuditLog, User
from app.services.admin_service import is_last_admin

log = get_logger(__name__)


async def _promote(email: str) -> int:
    normalized = email.strip().lower()
    async with session_scope() as db:
        user = await db.scalar(select(User).where(User.email == normalized))
        if user is None:
            print(f"No account with that address: {normalized}", file=sys.stderr)
            print(
                "The user must sign up first; this promotes an existing account.", file=sys.stderr
            )
            return 1

        if user.is_admin:
            print(f"{normalized} is already an administrator.")
            return 0

        user.is_admin = True
        # Same trail the panel writes for every other privileged change, so a
        # promotion made from a shell is not invisible in the UI.
        db.add(
            AdminAuditLog(
                actor_user_id=user.id,
                actor_email=user.email,
                action="admin.promoted",
                target_user_id=user.id,
                target_email=user.email,
                details={"source": "python -m app.manage promote-admin"},
            )
        )
        print(f"Promoted {normalized} to administrator.")
        return 0


async def _demote(email: str) -> int:
    normalized = email.strip().lower()
    async with session_scope() as db:
        user = await db.scalar(select(User).where(User.email == normalized))
        if user is None:
            print(f"No account with that address: {normalized}", file=sys.stderr)
            return 1
        if not user.is_admin:
            print(f"{normalized} is not an administrator.")
            return 0

        # Same check the admin panel's delete path uses, so the two can never
        # disagree about what would lock everyone out.
        if await is_last_admin(db, user):
            print(
                "Refusing to remove the only administrator — nobody could reach "
                "/admin afterwards. Promote a replacement first.",
                file=sys.stderr,
            )
            return 1

        user.is_admin = False
        db.add(
            AdminAuditLog(
                actor_user_id=user.id,
                actor_email=user.email,
                action="admin.demoted",
                target_user_id=user.id,
                target_email=user.email,
                details={"source": "python -m app.manage demote-admin"},
            )
        )
        print(f"Removed administrator rights from {normalized}.")
        return 0


async def _ensure_admin() -> int:
    """Create the first administrator if this deployment has none.

    The same call the web process makes on startup, exposed so a deploy script
    can run it explicitly and see the outcome. Idempotent: on every deploy after
    the first it prints that an administrator already exists and changes
    nothing.
    """
    from app.services.bootstrap_service import ensure_admin

    async with session_scope() as db:
        outcome = await ensure_admin(db)
        if outcome.changed:
            await db.commit()

    match outcome.action:
        case "created":
            print(f"Created administrator {outcome.email}.")
            print(outcome.detail)
            print("The password was emailed once and is not recoverable from here.")
            return 0
        case "promoted":
            print(f"Promoted {outcome.email} to administrator.")
            print(outcome.detail)
            return 0
        case "noop":
            print(f"Nothing to do: {outcome.detail}.")
            return 0
        case "locked":
            print(f"Another process is bootstrapping: {outcome.detail}.")
            return 0
        case _:
            print(f"Skipped: {outcome.detail}", file=sys.stderr)
            return 1


async def _test_email(recipient: str) -> int:
    """Send one message, to prove mail actually works before a user needs it.

    Worth having as its own command because the alternative is triggering a real
    password reset, which tells you nothing when it silently fails — the reset
    flow deliberately returns the same response whether or not delivery worked.
    This one reports the error.
    """
    from app.mail import EmailError, send_email

    settings = get_settings()

    print(f"backend : {settings.email_backend}")
    if settings.email_backend == "smtp":
        print(f"host    : {settings.smtp_host}:{settings.smtp_port}")
        print(f"starttls: {settings.smtp_use_tls}")
        print(f"auth    : {'yes' if settings.smtp_username else 'no'}")
    print(f"from    : {settings.email_from}")
    print(f"to      : {recipient}")
    print()

    if settings.email_backend == "console":
        print("EMAIL_BACKEND=console — this will be written to the log, not sent.")

    try:
        await send_email(
            to=recipient,
            subject="Weedout test message",
            text="\n".join(
                [
                    "This is a test message from your Weedout deployment.",
                    "",
                    "If it arrived, password resets and alert digests will too.",
                    "",
                    "Check that it did not land in spam — that is the failure",
                    "mode that looks like success.",
                    "",
                ]
            ),
            settings=settings,
        )
    except EmailError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        print(file=sys.stderr)
        print("Common causes:", file=sys.stderr)
        print("  * SMTP_HOST unreachable from this container", file=sys.stderr)
        print("  * relay rejecting the sender domain (ALLOWED_SENDER_DOMAINS)", file=sys.stderr)
        print("  * provider credentials wrong (MAIL_RELAYHOST_USERNAME/PASSWORD)", file=sys.stderr)
        return 1

    print("Handed off for delivery.")
    if settings.email_backend == "smtp":
        print()
        print("That means the relay accepted it, not that it reached the inbox.")
        print("Check the relay's own log for the onward hop:")
        print("  docker compose -f docker-compose.prod.yml logs mail | grep status=")
    return 0


async def _reseed_docs(force: bool) -> int:
    """Bring the built-in documentation pages up to date with this release.

    Seeding never overwrites, so improved starter copy does not reach a
    deployment that already has the pages. Without `--force` this only reports
    what differs, because a page an administrator has rewritten should not be
    replaced by a deploy step.
    """
    from app.services.docs_service import reseed_starter_pages, starter_page_drift

    async with session_scope() as db:
        drift = await starter_page_drift(db)

        if not drift:
            print("All built-in documentation pages already match this release.")
            return 0

        if not force:
            print("These built-in pages differ from this release's content:")
            for slug, exists in drift:
                state = "edited or outdated" if exists else "missing"
                print(f"  {slug:32} {state}")
            print()
            print("Re-run with --force to overwrite them. Any edits you made to")
            print("these pages in /admin/docs will be lost.")
            return 0

        updated = await reseed_starter_pages(db)
        await db.commit()

    for slug in updated:
        print(f"Updated {slug}")
    print(f"{len(updated)} page(s) rewritten.")
    return 0


async def _list_admins() -> int:
    async with session_scope() as db:
        admins = list((await db.scalars(select(User).where(User.is_admin.is_(True)))).all())

    configured = get_settings().admin_email
    if not admins:
        print("No administrators.")
        if configured:
            print(f"ADMIN_EMAIL is set to {configured}; it is promoted on first sign-in.")
        else:
            print("ADMIN_EMAIL is unset. Use `promote-admin <email>` to appoint one.")
        return 0

    for user in admins:
        marker = "  (from ADMIN_EMAIL)" if configured and user.email == configured else ""
        print(f"{user.email}{marker}")
    return 0


async def _main_async(args: argparse.Namespace) -> int:
    try:
        match args.command:
            case "promote-admin":
                return await _promote(args.email)
            case "demote-admin":
                return await _demote(args.email)
            case "ensure-admin":
                return await _ensure_admin()
            case "list-admins":
                return await _list_admins()
            case "reseed-docs":
                return await _reseed_docs(args.force)
            case "test-email":
                return await _test_email(args.recipient)
            case _:
                print(f"Unknown command: {args.command}", file=sys.stderr)
                return 2
    finally:
        await dispose_engine()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m app.manage", description="Weedout operator commands"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    promote = sub.add_parser("promote-admin", help="grant admin rights to an existing account")
    promote.add_argument("email")

    demote = sub.add_parser("demote-admin", help="revoke admin rights")
    demote.add_argument("email")

    sub.add_parser(
        "ensure-admin",
        help="create the first administrator if none exists (idempotent)",
    )
    sub.add_parser("list-admins", help="show current administrators")

    reseed = sub.add_parser(
        "reseed-docs",
        help="update the built-in docs pages to this release (reports by default)",
    )
    reseed.add_argument(
        "--force",
        action="store_true",
        help="actually overwrite them, discarding any edits made in /admin/docs",
    )

    test_email = sub.add_parser("test-email", help="send one message to check mail delivery works")
    test_email.add_argument("recipient")

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
