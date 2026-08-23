"""a severity floor of its own for dev-only dependencies

Revision ID: b7d3e91a4c62
Revises: a1c4f7e2d9b3
Create Date: 2026-08-23 21:40:00.000000

Dev-only findings were governed by a boolean: report all of them, or none.
Neither is what a team wants. A critical in a linter is not a critical in a web
framework — and it is not nothing either, so switching them off hides a
genuinely compromised build tool.

Null means the old behaviour, which is what every existing project keeps. The
column only becomes meaningful when somebody sets it, so this is additive with
no backfill and no change to any current scan's result.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b7d3e91a4c62"
down_revision: str | None = "a1c4f7e2d9b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tracked_targets",
        sa.Column("dev_threshold", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tracked_targets", "dev_threshold")
