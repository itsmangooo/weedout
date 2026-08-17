"""rate limit hits

Revision ID: d3c81f0a94e2
Revises: 05b0a721210d
Create Date: 2026-08-17 21:05:00.000000

Backs the login, signup and password-reset rate limits. Counted in Postgres
rather than in process memory because the app can run as more than one replica,
where an in-process counter would multiply every limit by the number of
processes and reset on each deploy.

The composite index is the whole point of the table: every check is
"count rows in this bucket since this timestamp", and that has to stay cheap
enough to run before the Argon2 verification on the sign-in path.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d3c81f0a94e2"
down_revision: str | None = "05b0a721210d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_hits",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("bucket", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rate_limit_hits")),
    )
    op.create_index(
        "ix_rate_limit_hits_bucket_created",
        "rate_limit_hits",
        ["bucket", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_rate_limit_hits_bucket_created", table_name="rate_limit_hits")
    op.drop_table("rate_limit_hits")
