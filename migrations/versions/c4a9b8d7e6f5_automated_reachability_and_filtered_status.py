"""automated reachability and filtered finding status

Revision ID: c4a9b8d7e6f5
Revises: f1e6b90c4a72
Create Date: 2026-08-29 12:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4a9b8d7e6f5"
down_revision: str | None = "018ca2ca7edd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tracked_targets", sa.Column("reachability_analyzed_at", sa.DateTime(timezone=True))
    )
    op.add_column(
        "tracked_targets",
        sa.Column("reachability_source_count", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "tracked_targets",
        sa.Column(
            "reachability_analysis_complete", sa.Boolean(), server_default="false", nullable=False
        ),
    )
    op.add_column(
        "tracked_targets",
        sa.Column(
            "reachability_analysis_notes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
    )

    for table in ("dependencies", "cve_matches"):
        op.add_column(
            table,
            sa.Column(
                "automated_reachability",
                sa.String(length=64),
                server_default="unknown",
                nullable=False,
            ),
        )
        op.add_column(
            table,
            sa.Column(
                "reachability_evidence",
                postgresql.JSONB(astext_type=sa.Text()),
                server_default="[]",
                nullable=False,
            ),
        )
        op.create_index(
            f"ix_{table}_automated_reachability", table, ["automated_reachability"], unique=False
        )

    # Suppressed rows used to inherit the model's generic OPEN default. They
    # are not active work and must never continue to look like it after this
    # release. Dismissed and resolved history is intentionally preserved.
    op.execute(
        "UPDATE cve_matches SET status = 'filtered' "
        "WHERE verdict = 'suppressed' AND status = 'open'"
    )


def downgrade() -> None:
    # The old application cannot read `filtered`; map it back only for schema
    # compatibility during a rollback. This does not make it actionable in the
    # upgraded application.
    op.execute("UPDATE cve_matches SET status = 'open' WHERE status = 'filtered'")

    for table in ("cve_matches", "dependencies"):
        op.drop_index(f"ix_{table}_automated_reachability", table_name=table)
        op.drop_column(table, "reachability_evidence")
        op.drop_column(table, "automated_reachability")

    op.drop_column("tracked_targets", "reachability_analysis_notes")
    op.drop_column("tracked_targets", "reachability_analysis_complete")
    op.drop_column("tracked_targets", "reachability_source_count")
    op.drop_column("tracked_targets", "reachability_analyzed_at")
