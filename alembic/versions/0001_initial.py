"""Initial schema.

Revision ID: 0001_initial
Revises: 
Create Date: 2026-01-06 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    storage_mode_enum = sa.Enum("none", "sampled", "full", name="storagemode")
    finding_status_enum = sa.Enum("open", "fixed", "soft_deleted", name="findingstatus")
    confidence_enum = sa.Enum("low", "medium", "high", name="confidence")
    audit_action_enum = sa.Enum(
        "scan.started",
        "scan.completed",
        "module.run",
        "export.generated",
        "exception.created",
        "exception.expired",
        "recheck.triggered",
        name="auditaction",
    )

    op.create_table(
        "target",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("base_url", sa.String(), nullable=False),
        sa.Column("environment", sa.String(), nullable=False),
        sa.Column("auth_profiles", sa.JSON(), nullable=False),
    )

    op.create_table(
        "scan",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("target_id", sa.String(), sa.ForeignKey("target.id"), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("profile_name", sa.String(), nullable=False),
        sa.Column("profile_capabilities", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("baseline_scan_id", sa.String(), sa.ForeignKey("scan.id"), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "endpoint",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scan.id"), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("params_hash", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "fetch",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("endpoint_id", sa.String(), sa.ForeignKey("endpoint.id"), nullable=False),
        sa.Column("request", sa.JSON(), nullable=False),
        sa.Column("response_meta", sa.JSON(), nullable=False),
        sa.Column("storage_mode", storage_mode_enum, nullable=False),
        sa.Column("redaction_version", sa.String(), nullable=False),
        sa.Column("body_path", sa.String(), nullable=True),
        sa.Column("body_hash", sa.String(), nullable=True),
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("fetch_id", sa.String(), sa.ForeignKey("fetch.id"), nullable=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("snippet", sa.String(), nullable=False),
        sa.Column("location", sa.String(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )

    op.create_table(
        "techcomponent",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("endpoint_id", sa.String(), sa.ForeignKey("endpoint.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("cpe", sa.String(), nullable=True),
        sa.Column("confidence", confidence_enum, nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
    )

    op.create_table(
        "cvecandidate",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("cpe", sa.String(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("confidence", confidence_enum, nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("linked_component_id", sa.String(), sa.ForeignKey("techcomponent.id"), nullable=True),
    )

    op.create_table(
        "finding",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("dedupe_key", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("confidence", confidence_enum, nullable=False),
        sa.Column("status", finding_status_enum, nullable=False),
        sa.Column("remediation", sa.String(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("cwe_id", sa.String(), nullable=True),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("fixed_at", sa.DateTime(), nullable=True),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("source_module", sa.String(), nullable=False),
    )
    op.create_index("ix_finding_dedupe_key", "finding", ["dedupe_key"])

    op.create_table(
        "exceptionrecord",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("finding_key", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("approver", sa.String(), nullable=False),
        sa.Column("ticket", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("owner", sa.String(), nullable=True),
    )
    op.create_index("ix_exceptionrecord_finding_key", "exceptionrecord", ["finding_key"])

    op.create_table(
        "auditevent",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("action", audit_action_enum, nullable=False),
        sa.Column("scan_id", sa.String(), sa.ForeignKey("scan.id"), nullable=True),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("immutable", sa.Boolean(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("auditevent")
    op.drop_index("ix_exceptionrecord_finding_key", table_name="exceptionrecord")
    op.drop_table("exceptionrecord")
    op.drop_index("ix_finding_dedupe_key", table_name="finding")
    op.drop_table("finding")
    op.drop_table("cvecandidate")
    op.drop_table("techcomponent")
    op.drop_table("evidence")
    op.drop_table("fetch")
    op.drop_table("endpoint")
    op.drop_table("scan")
    op.drop_table("target")

    op.execute("DROP TYPE IF EXISTS auditaction")
    op.execute("DROP TYPE IF EXISTS confidence")
    op.execute("DROP TYPE IF EXISTS findingstatus")
    op.execute("DROP TYPE IF EXISTS storagemode")
