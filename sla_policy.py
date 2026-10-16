
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class SLAPolicy(Base):
    __tablename__ = "sla_policies"
    __table_args__ = (
        UniqueConstraint("severity", name="uq_sla_policy_severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )
    acknowledgment_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    investigation_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    resolution_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    escalation_after_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=15
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
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
