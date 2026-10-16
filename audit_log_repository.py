from sqlalchemy import func, select
from sqlalchemy.orm import Session

from models.audit_log import AuditLog


class AuditLogRepository:
    """Database operations for audit logs."""

    @staticmethod
    def get_latest(db: Session) -> AuditLog | None:
        statement = (
            select(AuditLog)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        return db.scalar(statement)

    @staticmethod
    def get_by_id(db: Session, audit_log_id: int) -> AuditLog | None:
        return db.get(AuditLog, audit_log_id)

    @staticmethod
    def list_logs(
        db: Session,
        *,
        user_id: int | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditLog], int]:
        statement = select(AuditLog)
        count_statement = select(func.count()).select_from(AuditLog)

        if user_id is not None:
            statement = statement.where(AuditLog.user_id == user_id)
            count_statement = count_statement.where(
                AuditLog.user_id == user_id
            )

        if action is not None:
            statement = statement.where(AuditLog.action == action)
            count_statement = count_statement.where(
                AuditLog.action == action
            )

        if entity_type is not None:
            statement = statement.where(
                AuditLog.entity_type == entity_type
            )
            count_statement = count_statement.where(
                AuditLog.entity_type == entity_type
            )

        if entity_id is not None:
            statement = statement.where(AuditLog.entity_id == entity_id)
            count_statement = count_statement.where(
                AuditLog.entity_id == entity_id
            )

        statement = (
            statement
            .order_by(AuditLog.id.desc())
            .offset(offset)
            .limit(limit)
        )

        logs = list(db.scalars(statement).all())
        total = db.scalar(count_statement) or 0

        return logs, total
