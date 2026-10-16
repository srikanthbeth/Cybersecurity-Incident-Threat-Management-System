
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def utc_now():
    return datetime.now(timezone.utc)


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"
    __table_args__ = (
        Index("ix_remediation_status_priority", "status", "priority"),
        Index("ix_remediation_due_status", "due_at", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    task_number: Mapped[str] = mapped_column(
        String(40), unique=True, nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    vulnerability_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )

    assigned_team_id: Mapped[int] = mapped_column(
        ForeignKey("security_teams.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    assigned_to: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )

    priority: Mapped[str] = mapped_column(
        String(20), default="MEDIUM", nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), default="OPEN", nullable=False, index=True
    )
    due_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    submitted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )
