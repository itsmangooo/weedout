"""Operator CLI: ``python -m app.manage <command>``.

Commands that need a human decision and should never be reachable from the web
UI. Chiefly admin bootstrap — there is no "become admin" page precisely because
privilege escalation should require shell access to the host, not a browser.

    python -m app.manage promote-admin you@example.com
    python -m app.manage demote-admin  you@example.com
    python -m app.manage list-admins
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
            case "list-admins":
                return await _list_admins()
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

    sub.add_parser("list-admins", help="show current administrators")

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
