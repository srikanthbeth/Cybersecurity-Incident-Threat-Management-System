from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InvestigationStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class InvestigationPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceType(str, Enum):
    LOG = "LOG"
    SCREENSHOT = "SCREENSHOT"
    DOCUMENT = "DOCUMENT"
    NETWORK_CAPTURE = "NETWORK_CAPTURE"
    HASH = "HASH"
    URL = "URL"
    OTHER = "OTHER"


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=5, max_length=10000)
    priority: InvestigationPriority = InvestigationPriority.MEDIUM
    incident_id: int | None = Field(default=None, gt=0)
    alert_id: int | None = Field(default=None, gt=0)
    asset_id: int | None = Field(default=None, gt=0)
    assigned_to: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def require_related_record(self):
        if not any(
            value is not None
            for value in (self.incident_id, self.alert_id, self.asset_id)
        ):
            raise ValueError(
                "At least one of incident_id, alert_id, or asset_id is required"
            )
        return self


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, min_length=5, max_length=10000)
    priority: InvestigationPriority | None = None
    status: InvestigationStatus | None = None
    assigned_to: int | None = Field(default=None, gt=0)


class InvestigationNoteCreate(BaseModel):
    note: str = Field(min_length=2, max_length=10000)


class InvestigationNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    author_id: int
    note: str
    created_at: datetime


class EvidenceCreate(BaseModel):
    reference: str = Field(min_length=1, max_length=1000)
    evidence_type: EvidenceType
    description: str = Field(min_length=3, max_length=5000)
    is_sensitive: bool = True


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    reference: str
    evidence_type: str
    description: str
    is_sensitive: bool
    recorded_by: int
    created_at: datetime


class InvestigationHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    actor_id: int
    action: str
    details: str | None
    created_at: datetime


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_number: str
    title: str
    description: str
    status: str
    priority: str
    incident_id: int | None
    alert_id: int | None
    asset_id: int | None
    assigned_to: int | None
    created_by: int
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime