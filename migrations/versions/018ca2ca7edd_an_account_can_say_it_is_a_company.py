"""an account can say it is a company, and ask to be named for it

Revision ID: 018ca2ca7edd
Revises: 32f55890a455

A label, not a capability. Nothing about the plan, the limits or what an
account may do changes with `account_kind` -- it exists so invoices, support
and the interface can say the right thing, and so "are you a company?" is asked
once rather than inferred from an email domain.

Explicitly not a team. One login, one set of credentials, no members. That is a
materially larger feature and calling this one a team would promise all of it.

`showcase_opt_in` and `showcase_approved_at` are two halves of one gate, and
both are required before a name appears anywhere public. Consent alone would
let somebody sign up as a well-known company and land on our front page.
Approval alone would be us publishing a customer without asking -- which for a
security product means disclosing that they scan their dependencies with us,
information that is theirs to give and not ours.

Additive. Every existing account is personal, opted out, and unapproved, which
is what they all are today.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "018ca2ca7edd"
down_revision: str | None = "32f55890a455"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("account_kind", sa.String(length=64), server_default="personal", nullable=False),
    )
    op.add_column("users", sa.Column("organisation_name", sa.String(length=200), nullable=True))
    op.add_column("users", sa.Column("organisation_website", sa.String(length=300), nullable=True))
    op.add_column(
        "users", sa.Column("showcase_opt_in", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column(
        "users", sa.Column("showcase_approved_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("users", "showcase_approved_at")
    op.drop_column("users", "showcase_opt_in")
    op.drop_column("users", "organisation_website")
    op.drop_column("users", "organisation_name")
    op.drop_column("users", "account_kind")
