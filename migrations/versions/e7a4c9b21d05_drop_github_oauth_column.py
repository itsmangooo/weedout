"""drop the github oauth identity column

Revision ID: e7a4c9b21d05
Revises: d3c81f0a94e2
Create Date: 2026-08-17 22:10:00.000000

GitHub sign-in was never finished and has been removed rather than left
half-present. `users.github_id` was the column an implementation would have
linked accounts on, and leaving it in place is what would let someone re-enable
the feature later without re-solving the question that stopped it: linking a
GitHub account to an existing password account by matching email addresses is
an account-takeover path unless the address is known-verified on both sides.

Dropping the column means that decision has to be made again, deliberately,
before anything can be linked to anything.

Safe on live data: nothing ever wrote to it, so every row holds NULL.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e7a4c9b21d05"
down_revision: str | None = "d3c81f0a94e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Guard rather than assume. If a future branch ever did populate this, the
    # migration should stop rather than silently discard identities.
    populated = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM users WHERE github_id IS NOT NULL")
    )
    if populated:
        raise RuntimeError(
            f"{populated} user(s) have a github_id set. Refusing to drop the column — "
            "resolve those accounts first."
        )

    op.drop_constraint("uq_users_github_id", "users", type_="unique")
    op.drop_column("users", "github_id")


def downgrade() -> None:
    op.add_column("users", sa.Column("github_id", sa.String(length=64), nullable=True))
    op.create_unique_constraint("uq_users_github_id", "users", ["github_id"])
