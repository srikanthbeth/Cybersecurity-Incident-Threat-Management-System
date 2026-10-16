
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(str, Enum):
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT = "CONTAINMENT"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentCategory(str, Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    NETWORK_INTRUSION = "NETWORK_INTRUSION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    VULNERABILITY = "VULNERABILITY"
    OTHER = "OTHER"


class IncidentCreate(BaseModel):
    alert_id: int
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=5)
    category: IncidentCategory
    severity: IncidentSeverity
    assigned_to: int | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, min_length=5)
    category: IncidentCategory | None = None
    severity: IncidentSeverity | None = None
    assigned_to: int | None = None
    status: IncidentStatus | None = None
    resolution_details: str | None = Field(default=None, min_length=5)


class IncidentNoteCreate(BaseModel):
    note: str = Field(min_length=2, max_length=10000)


class ClosureRequest(BaseModel):
    details: str | None = Field(default=None, max_length=2000)


class IncidentNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    author_id: int
    note: str
    created_at: datetime


class IncidentHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    actor_id: int
    action: str
    old_value: str | None
    new_value: str | None
    details: str | None
    created_at: datetime


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_number: str
    title: str
    description: str
    category: str
    severity: str
    status: str
    organization_id: int | None
    assigned_to: int | None
    created_by: int
    resolved_by: int | None
    resolution_details: str | None
    resolved_at: datetime | None
    closure_requested_by: int | None
    closure_requested_at: datetime | None
    closure_approved_by: int | None
    closure_approved_at: datetime | None
    created_at: datetime
    updated_at: datetime
