"""a project watches many manifests

Revision ID: a1c4f7e2d9b3
Revises: e48a017523ca
Create Date: 2026-08-23 15:10:00.000000

A project has been exactly one file since the beginning: `manifest_kind`,
`manifest_content` and `content_hash` on `tracked_targets`. That is the wrong
shape for the ordinary case — a repository with a Go backend and an npm
frontend is one project to the person who owns it and two files to the scanner
— and it is what stands between here and supporting more ecosystems, because
"which ecosystem is this project" stops having a single answer.

The interesting part of this migration is the two unique constraints that move.

`dependencies` was unique on (target, name, version). Two manifests in one
project can legitimately contain the same package at the same version, and —
more sharply — the same *name* can exist in two ecosystems: `requests` is a
real package on both PyPI and npm. Keyed on the project alone those collapse
into one row whose `ecosystem` is whichever parse ran last, which would make
the scanner look up the wrong advisories. The key becomes the manifest.

`cve_matches` moves for a related but different reason: "which file do I fix
this in" is the actionable half of a finding. In a monorepo the same vulnerable
package in two lockfiles is two pieces of work, probably for two people.

Existing data is preserved. Every target that has a manifest gets exactly one
`project_manifests` row holding what used to be on the target, and every
dependency and match is pointed at it. Targets with no manifest yet — a real
and supported state — get no row, and their (empty) dependency and match sets
have nothing to point anywhere.

The old columns on `tracked_targets` are left in place and unused by this
revision. Dropping them is a separate, later migration: doing it here would
make the downgrade lossy and would break any process still mid-deploy.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1c4f7e2d9b3"
down_revision: str | None = "e48a017523ca"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "project_manifests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(length=400), nullable=False),
        # `enum_column` persists these as CHECK-constrained VARCHAR rather than
        # native Postgres enums, so that adding an ecosystem is a code change
        # and not a type migration. Matching that here matters: declaring them
        # as sa.Enum would create a type the rest of the schema does not use.
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("ecosystem", sa.String(length=64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("dependency_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "parse_warnings", sa.dialects.postgresql.JSONB(), server_default="[]", nullable=False
        ),
        sa.Column("last_parsed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_parse_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["target_id"], ["tracked_targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id", "path", name="uq_manifest_target_path"),
    )
    op.create_index("ix_project_manifests_target_id", "project_manifests", ["target_id"])
    op.create_index("ix_project_manifests_target", "project_manifests", ["target_id", "is_active"])
    op.create_index("ix_project_manifests_content_hash", "project_manifests", ["content_hash"])

    # One row per target that has a file. The path is the bare filename: it is
    # all we ever knew, and it is what a single-manifest project would have
    # been called anyway.
    op.execute(
        """
        INSERT INTO project_manifests (
            target_id, path, kind, ecosystem, content, content_hash,
            is_active, dependency_count, parse_warnings, last_parsed_at,
            last_parse_error, created_at, updated_at
        )
        SELECT
            id,
            manifest_kind::text,
            manifest_kind,
            ecosystem,
            manifest_content,
            COALESCE(content_hash, encode(sha256(manifest_content::bytea), 'hex')),
            is_active,
            dependency_count,
            parse_warnings,
            last_scanned_at,
            last_scan_error,
            created_at,
            updated_at
        FROM tracked_targets
        WHERE manifest_content IS NOT NULL AND manifest_kind IS NOT NULL
        """
    )

    # --- dependencies ------------------------------------------------------

    op.add_column("dependencies", sa.Column("manifest_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE dependencies AS d
        SET manifest_id = m.id
        FROM project_manifests AS m
        WHERE m.target_id = d.target_id
        """
    )
    # A dependency whose target somehow has no manifest cannot be pointed
    # anywhere and describes a parse that can never be reproduced.
    op.execute("DELETE FROM dependencies WHERE manifest_id IS NULL")
    op.alter_column("dependencies", "manifest_id", nullable=False)
    op.create_foreign_key(
        "fk_dependencies_manifest_id",
        "dependencies",
        "project_manifests",
        ["manifest_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_dependencies_manifest_id", "dependencies", ["manifest_id"])
    op.drop_constraint("uq_dependency_target_name_version", "dependencies", type_="unique")
    op.create_unique_constraint(
        "uq_dependency_manifest_name_version",
        "dependencies",
        ["manifest_id", "name", "version"],
    )

    # --- cve_matches -------------------------------------------------------

    op.add_column("cve_matches", sa.Column("manifest_id", sa.Integer(), nullable=True))
    op.execute(
        """
        UPDATE cve_matches AS c
        SET manifest_id = m.id
        FROM project_manifests AS m
        WHERE m.target_id = c.target_id
        """
    )
    op.execute("DELETE FROM cve_matches WHERE manifest_id IS NULL")
    op.alter_column("cve_matches", "manifest_id", nullable=False)
    op.create_foreign_key(
        "fk_cve_matches_manifest_id",
        "cve_matches",
        "project_manifests",
        ["manifest_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_cve_matches_manifest_id", "cve_matches", ["manifest_id"])
    op.drop_constraint("uq_cve_match_identity", "cve_matches", type_="unique")
    op.create_unique_constraint(
        "uq_cve_match_identity",
        "cve_matches",
        ["manifest_id", "package_name", "package_version", "vulnerability_id"],
    )


def downgrade() -> None:
    # Lossy by nature: a project with more than one manifest cannot be
    # expressed in the old shape. The first manifest wins and the rest are
    # dropped, which is the only answer available — so this is a rollback for
    # a deployment that has not yet added a second file to anything.
    op.drop_constraint("uq_cve_match_identity", "cve_matches", type_="unique")
    op.create_unique_constraint(
        "uq_cve_match_identity",
        "cve_matches",
        ["target_id", "package_name", "package_version", "vulnerability_id"],
    )
    op.drop_index("ix_cve_matches_manifest_id", table_name="cve_matches")
    op.drop_constraint("fk_cve_matches_manifest_id", "cve_matches", type_="foreignkey")
    op.drop_column("cve_matches", "manifest_id")

    op.drop_constraint("uq_dependency_manifest_name_version", "dependencies", type_="unique")
    op.create_unique_constraint(
        "uq_dependency_target_name_version",
        "dependencies",
        ["target_id", "name", "version"],
    )
    op.drop_index("ix_dependencies_manifest_id", table_name="dependencies")
    op.drop_constraint("fk_dependencies_manifest_id", "dependencies", type_="foreignkey")
    op.drop_column("dependencies", "manifest_id")

    op.drop_index("ix_project_manifests_content_hash", table_name="project_manifests")
    op.drop_index("ix_project_manifests_target", table_name="project_manifests")
    op.drop_index("ix_project_manifests_target_id", table_name="project_manifests")
    op.drop_table("project_manifests")
