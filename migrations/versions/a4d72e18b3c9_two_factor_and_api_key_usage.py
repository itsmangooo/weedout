"""Two-factor authentication, recovery codes, and API key call counts.

Revision ID: a4d72e18b3c9
Revises: f1e6b90c4a72

Everything here is additive and nullable, or has a server default, so the
migration is safe to run against a live database while the previous version of
the application is still serving: an old process writing rows that know nothing
about these columns produces valid rows.

The downgrade refuses to run if any account actually has 2FA switched on.
Dropping `totp_secret` from an account that is relying on it does not turn 2FA
off — it turns the account into one that demands a code nobody can generate.
Better to stop and make that a deliberate decision.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a4d72e18b3c9"
down_revision = "f1e6b90c4a72"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret", sa.String(length=64), nullable=True))
    op.add_column(
        "users", sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("users", sa.Column("totp_last_counter", sa.BigInteger(), nullable=True))

    op.add_column(
        "api_keys",
        sa.Column("call_count", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "backup_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_backup_codes_user_id", "backup_codes", ["user_id"])
    op.create_index("ix_backup_codes_code_hash", "backup_codes", ["code_hash"])


def downgrade() -> None:
    bind = op.get_bind()
    enabled = bind.execute(
        sa.text("SELECT count(*) FROM users WHERE totp_confirmed_at IS NOT NULL")
    ).scalar_one()
    if enabled:
        raise RuntimeError(
            f"Refusing to downgrade: {enabled} account(s) have two-factor authentication "
            "enabled. Dropping these columns would leave them demanding a code that can no "
            "longer be verified. Disable 2FA on those accounts first."
        )

    op.drop_index("ix_backup_codes_code_hash", table_name="backup_codes")
    op.drop_index("ix_backup_codes_user_id", table_name="backup_codes")
    op.drop_table("backup_codes")

    op.drop_column("api_keys", "call_count")
    op.drop_column("users", "totp_last_counter")
    op.drop_column("users", "totp_confirmed_at")
    op.drop_column("users", "totp_secret")
