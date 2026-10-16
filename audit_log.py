from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditLogBase(BaseModel):
    action: str = Field(min_length=1, max_length=100)
    entity_type: str = Field(min_length=1, max_length=100)
    entity_id: str | None = Field(default=None, max_length=100)
    previous_value: dict[str, Any] | list[Any] | None = None
    new_value: dict[str, Any] | list[Any] | None = None
    ip_address: str | None = Field(default=None, max_length=45)
    user_agent: str | None = None
    request_id: str | None = Field(default=None, max_length=100)


class AuditLogCreate(AuditLogBase):
    """Input schema for creating an audit event internally."""
    user_id: int | None = None


class AuditLogResponse(AuditLogBase):
    """Audit log returned by the API."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None = None
    previous_hash: str | None = None
    record_hash: str
    created_at: datetime


class AuditLogListResponse(BaseModel):
    """Paginated audit log results."""
    items: list[AuditLogResponse]
    total: int
    limit: int
    offset: int


class AuditLogVerifyResponse(BaseModel):
    """Result of audit hash-chain verification."""
    valid: bool
    checked_records: int
    first_invalid_record_id: int | None = None
    message: str
