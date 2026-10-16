
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


def utc_now():
    return datetime.now(timezone.utc)


class AlertCorrelationMember(Base):
    __tablename__ = "alert_correlation_members"
    __table_args__ = (
        UniqueConstraint(
            "group_id",
            "alert_id",
            name="uq_correlation_group_alert",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    group_id: Mapped[int] = mapped_column(
        ForeignKey("alert_correlation_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("security_alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    added_by: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    group = relationship("AlertCorrelationGroup", back_populates="members")
    alert = relationship("Alert")
