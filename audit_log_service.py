
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.audit_log import AuditLog
from repositories.audit_log_repository import AuditLogRepository
from schemas.audit_log import AuditLogCreate


class AuditLogService:
    """Create and verify tamper-evident audit records."""

    HASH_FIELDS = (
        "id",
        "user_id",
        "action",
        "entity_type",
        "entity_id",
        "previous_value",
        "new_value",
        "ip_address",
        "user_agent",
        "request_id",
        "previous_hash",
        "created_at",
    )

    @staticmethod
    def normalize_datetime(value: datetime) -> str:
        """Serialize timestamps consistently in UTC."""
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        else:
            value = value.astimezone(timezone.utc)

        return value.isoformat(timespec="microseconds")

    @classmethod
    def calculate_hash(cls, log: AuditLog) -> str:
        """Calculate a deterministic SHA-256 hash for an audit record."""
        data: dict[str, Any] = {}

        for field in cls.HASH_FIELDS:
            value = getattr(log, field)

            if isinstance(value, datetime):
                value = cls.normalize_datetime(value)

            data[field] = value

        canonical_json = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

        return hashlib.sha256(
            canonical_json.encode("utf-8")
        ).hexdigest()

    @classmethod
    def create(
        cls,
        db: Session,
        payload: AuditLogCreate,
    ) -> AuditLog:
        """
        Add an audit record to the current database transaction.

        The caller is responsible for committing or rolling back.
        """
        previous = AuditLogRepository.get_latest(db)

        log = AuditLog(
            **payload.model_dump(),
            previous_hash=(
                previous.record_hash if previous else None
            ),
            record_hash="",
            created_at=datetime.now(timezone.utc),
        )

        db.add(log)

        # Obtain the database-generated ID and persist field values.
        db.flush()

        # Refresh the timestamp so hashing uses the database value.
        db.refresh(log, attribute_names=["created_at"])

        log.record_hash = cls.calculate_hash(log)

        db.flush()

        return log

    @classmethod
    def verify_chain(cls, db: Session) -> dict[str, Any]:
        """Verify record hashes and links in ascending ID order."""
        statement = select(AuditLog).order_by(AuditLog.id.asc())
        logs = list(db.scalars(statement).all())

        expected_previous_hash: str | None = None

        for checked_count, log in enumerate(logs, start=1):
            if log.previous_hash != expected_previous_hash:
                return {
                    "valid": False,
                    "checked_records": checked_count,
                    "first_invalid_record_id": log.id,
                    "message": (
                        "Audit hash-chain link mismatch at "
                        f"record {log.id}."
                    ),
                }

            expected_hash = cls.calculate_hash(log)

            if (
                not log.record_hash
                or log.record_hash != expected_hash
            ):
                return {
                    "valid": False,
                    "checked_records": checked_count,
                    "first_invalid_record_id": log.id,
                    "message": (
                        f"Audit record {log.id} has an invalid hash."
                    ),
                }

            expected_previous_hash = log.record_hash

        return {
            "valid": True,
            "checked_records": len(logs),
            "first_invalid_record_id": None,
            "message": "Audit hash chain verified successfully.",
        }
