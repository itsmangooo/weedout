"""a named set of scan rules, reusable across projects

Revision ID: b152c68c5330
Revises: 3e9a08c91352
Create Date: 2026-08-24 00:49:50.935574

A team with eight services wants the same floors on all of them, a looser set
on the internal tools, and something stricter on the one facing the internet.
Per-project configuration means eight copies that drift, and changing the
standard means eight edits.

A profile holds a policy document in `.weedout.yml` syntax rather than a column
per setting: one syntax, one parser, and a working file can be lifted into a
profile by copying it.

Purely additive. `tracked_targets.profile_id` is null for every existing
project, which means "follow the account default" -- and there is no account
default until somebody makes one, so nothing changes until it is used.

The partial unique index is what makes "which profile applies when nobody said"
have exactly one answer, including when two requests try to set a default at
the same moment.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b152c68c5330"
down_revision: str | None = "3e9a08c91352"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rule_profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=False),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_rule_profiles_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rule_profiles")),
        sa.UniqueConstraint("user_id", "slug", name="uq_rule_profile_slug"),
    )
    op.create_index(op.f("ix_rule_profiles_user_id"), "rule_profiles", ["user_id"], unique=False)
    op.create_index(
        "uq_rule_profile_default",
        "rule_profiles",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("is_default"),
    )
    op.add_column("tracked_targets", sa.Column("profile_id", sa.Integer(), nullable=True))
    op.create_index(
        op.f("ix_tracked_targets_profile_id"), "tracked_targets", ["profile_id"], unique=False
    )
    op.create_foreign_key(
        op.f("fk_tracked_targets_profile_id_rule_profiles"),
        "tracked_targets",
        "rule_profiles",
        ["profile_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_tracked_targets_profile_id_rule_profiles"), "tracked_targets", type_="foreignkey"
    )
    op.drop_index(op.f("ix_tracked_targets_profile_id"), table_name="tracked_targets")
    op.drop_column("tracked_targets", "profile_id")
    op.drop_index(
        "uq_rule_profile_default",
        table_name="rule_profiles",
        postgresql_where=sa.text("is_default"),
    )
    op.drop_index(op.f("ix_rule_profiles_user_id"), table_name="rule_profiles")
    op.drop_table("rule_profiles")
