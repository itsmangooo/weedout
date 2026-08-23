"""a machine credential a developer confirms in a browser

Revision ID: 32f55890a455
Revises: b152c68c5330

Two tables for one flow.

`cli_tokens` is an account-level credential, deliberately not an `ApiKey`.
Every API key is scoped to one project, because a key leaked from a CI runner
should reach the one project that runner builds. This is the opposite kind of
credential: it belongs to a person at a keyboard and exists to do the things
that have no project yet -- create one, list them, mint a key for one. Keeping
them as separate tables means neither can be widened into the other by getting
a boolean wrong.

`cli_auth_requests` is one in-progress confirmation. It holds two secrets doing
different jobs: a short `user_code` a person reads and compares, and a hashed
256-bit device code only the waiting process knows. Knowing the code somebody
read aloud is not enough to collect the token.

Purely additive. Nothing reads either table until the flow ships.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "32f55890a455"
down_revision: str | None = "b152c68c5330"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cli_auth_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_code", sa.String(length=16), nullable=False),
        sa.Column("device_code_hash", sa.String(length=64), nullable=False),
        sa.Column("approved_by_user_id", sa.Integer(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("denied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("device_label", sa.String(length=120), server_default="", nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["approved_by_user_id"],
            ["users.id"],
            name=op.f("fk_cli_auth_requests_approved_by_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cli_auth_requests")),
    )
    op.create_index(
        "ix_cli_auth_pending", "cli_auth_requests", ["user_code", "expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_cli_auth_requests_approved_by_user_id"),
        "cli_auth_requests",
        ["approved_by_user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_cli_auth_requests_device_code_hash"),
        "cli_auth_requests",
        ["device_code_hash"],
        unique=True,
    )
    op.create_index(
        op.f("ix_cli_auth_requests_expires_at"), "cli_auth_requests", ["expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_cli_auth_requests_user_code"), "cli_auth_requests", ["user_code"], unique=True
    )
    op.create_table(
        "cli_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=24), nullable=False),
        sa.Column("device_label", sa.String(length=120), server_default="", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_cli_tokens_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cli_tokens")),
    )
    op.create_index(op.f("ix_cli_tokens_token_hash"), "cli_tokens", ["token_hash"], unique=True)
    op.create_index(
        "ix_cli_tokens_user_active", "cli_tokens", ["user_id", "revoked_at"], unique=False
    )
    op.create_index(op.f("ix_cli_tokens_user_id"), "cli_tokens", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_cli_tokens_user_id"), table_name="cli_tokens")
    op.drop_index("ix_cli_tokens_user_active", table_name="cli_tokens")
    op.drop_index(op.f("ix_cli_tokens_token_hash"), table_name="cli_tokens")
    op.drop_table("cli_tokens")
    op.drop_index(op.f("ix_cli_auth_requests_user_code"), table_name="cli_auth_requests")
    op.drop_index(op.f("ix_cli_auth_requests_expires_at"), table_name="cli_auth_requests")
    op.drop_index(op.f("ix_cli_auth_requests_device_code_hash"), table_name="cli_auth_requests")
    op.drop_index(op.f("ix_cli_auth_requests_approved_by_user_id"), table_name="cli_auth_requests")
    op.drop_index("ix_cli_auth_pending", table_name="cli_auth_requests")
    op.drop_table("cli_auth_requests")
