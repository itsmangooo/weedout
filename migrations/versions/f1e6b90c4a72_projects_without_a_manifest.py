"""allow projects to exist before their first manifest

Revision ID: f1e6b90c4a72
Revises: e7a4c9b21d05
Create Date: 2026-08-18 21:40:00.000000

A project had to be created *from* a manifest, which meant the file always came
first. That is backwards for the CLI flow: an API key is scoped to a project, so
the project has to exist before CI can push anything to it — and requiring an
upload forced every user through the browser once before they could use the tool
they came for.

Making these three columns nullable is what lets a project be created from a
name and an ecosystem alone. `ecosystem` deliberately stays NOT NULL: it is
chosen at creation and an uploaded file that disagrees is refused, because
switching it would silently reinterpret every finding already recorded.

Widening only. Every existing row has all three set, so this cannot fail and
nothing needs backfilling.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f1e6b90c4a72"
down_revision: str | None = "e7a4c9b21d05"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("tracked_targets", "manifest_content", existing_type=sa.Text(), nullable=True)
    op.alter_column(
        "tracked_targets", "content_hash", existing_type=sa.String(length=64), nullable=True
    )
    op.alter_column(
        "tracked_targets",
        "manifest_kind",
        existing_type=sa.String(length=64),
        nullable=True,
    )


def downgrade() -> None:
    # Narrowing, so it can fail where the upgrade could not: any project created
    # without a manifest has nulls in these columns and no value to invent.
    # Refuse rather than fabricate an empty manifest, which would read as a
    # scanned-and-clean project.
    remaining = op.get_bind().scalar(
        sa.text("SELECT count(*) FROM tracked_targets WHERE manifest_content IS NULL")
    )
    if remaining:
        raise RuntimeError(
            f"{remaining} project(s) have no manifest yet. Delete them or upload a "
            "manifest for each before downgrading."
        )

    op.alter_column(
        "tracked_targets",
        "manifest_kind",
        existing_type=sa.String(length=64),
        nullable=False,
    )
    op.alter_column(
        "tracked_targets", "content_hash", existing_type=sa.String(length=64), nullable=False
    )
    op.alter_column("tracked_targets", "manifest_content", existing_type=sa.Text(), nullable=False)
