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


class RiskAssessmentHistory(Base):
    __tablename__ = "risk_assessment_history"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("risk_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(60), nullable=False, index=True
    )
    previous_score: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    new_score: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    previous_level: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    new_level: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )
    details: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )