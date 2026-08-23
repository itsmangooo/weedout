"""an ignore rule may name a package glob, not only an advisory

Revision ID: 3e9a08c91352
Revises: b7d3e91a4c62
Create Date: 2026-08-24 00:28:09.641721

Ignoring by advisory id cannot serve the case it is most often reached for. A
private package mirrored under a name that also exists on the public registry
matches advisories for somebody else's code, and there is no fixed list of ids
to enumerate: the next advisory that other project publishes is a new one.

Additive and backwards compatible. `kind` defaults to `advisory`, which is what
every existing row is, so no rule changes meaning. `identifier` grows to 256
because a scoped package name plus glob syntax does not fit in 64.

Enums are stored as plain VARCHAR here (see `enum_column`), so `sa.String` is
what the column actually is -- `sa.Enum` would compare as a different type
against the existing schema.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "3e9a08c91352"
down_revision: str | None = "b7d3e91a4c62"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "ignore_rules",
        sa.Column(
            "kind",
            sa.String(length=64),
            nullable=False,
            server_default="advisory",
        ),
    )
    op.alter_column(
        "ignore_rules",
        "identifier",
        existing_type=sa.VARCHAR(length=64),
        type_=sa.String(length=256),
        existing_nullable=False,
    )
    op.drop_constraint("uq_ignore_rule_identity", "ignore_rules", type_="unique")
    op.create_unique_constraint(
        "uq_ignore_rule_identity",
        "ignore_rules",
        ["target_id", "kind", "identifier"],
    )


def downgrade() -> None:
    # Package rules have no representation in the old schema, and several could
    # collide on (target_id, identifier) with an advisory rule of the same
    # name. Removing them is the only honest way back, and it loses only rules
    # that could not have existed before this migration ran.
    op.execute(sa.text("DELETE FROM ignore_rules WHERE kind = 'package'"))
    op.execute(sa.text("DELETE FROM ignore_rules WHERE length(identifier) > 64"))

    op.drop_constraint("uq_ignore_rule_identity", "ignore_rules", type_="unique")
    op.create_unique_constraint(
        "uq_ignore_rule_identity",
        "ignore_rules",
        ["target_id", "identifier"],
    )
    op.alter_column(
        "ignore_rules",
        "identifier",
        existing_type=sa.String(length=256),
        type_=sa.VARCHAR(length=64),
        existing_nullable=False,
    )
    op.drop_column("ignore_rules", "kind")
