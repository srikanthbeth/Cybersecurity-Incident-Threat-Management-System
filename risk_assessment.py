from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def utc_now():
    return datetime.now(timezone.utc)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    highest_risk_vulnerability_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    assessed_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    asset_criticality: Mapped[str] = mapped_column(
        String(20), nullable=False
    )
    vulnerability_severity: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    risk_score: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False, default="LOW", index=True
    )
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="OPEN", index=True
    )
    assessment_details: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    accepted_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    accepted_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    remediation_notes: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    remediated_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    remediated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )