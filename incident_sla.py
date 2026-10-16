
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class IncidentSLA(Base):
    __tablename__ = "incident_slas"
    __table_args__ = (
        UniqueConstraint("incident_id", name="uq_incident_sla_incident"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    policy_id: Mapped[int | None] = mapped_column(
        ForeignKey("sla_policies.id", ondelete="SET NULL"),
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    acknowledgment_deadline: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    investigation_deadline: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    resolution_deadline: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    investigation_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    actual_response_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    actual_investigation_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    actual_resolution_minutes: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    acknowledgment_breached: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    investigation_breached: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    resolution_breached: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    breach_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="ON_TRACK", index=True
    )

    escalation_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="NOT_REQUIRED", index=True
    )
    escalated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
