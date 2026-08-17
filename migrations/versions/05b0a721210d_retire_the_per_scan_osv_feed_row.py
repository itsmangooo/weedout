"""retire the per-scan osv feed row

Revision ID: 05b0a721210d
Revises: a2bfb3b26c6f
Create Date: 2026-08-17 20:41:00.000000

Advisories used to be fetched from OSV during each scan, and the health of that
path was recorded on a `feed_syncs` row named `osv`. The local mirror replaced
it: nothing writes that row any more, and the admin panel now lists one row per
mirrored ecosystem instead.

Left in place the row would be a feed that is permanently frozen at whatever it
last recorded — reading as healthy to anyone querying the table directly, while
describing a code path that no longer exists. Removing it is the whole change;
there is no schema difference.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "05b0a721210d"
down_revision: str | None = "a2bfb3b26c6f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DELETE FROM feed_syncs WHERE name = 'osv'")


def downgrade() -> None:
    # Deliberately empty. The row held observations about a code path that no
    # longer exists, so recreating it would invent data rather than restore it.
    # A downgrade leaves the table one row lighter, which is correct.
    pass
