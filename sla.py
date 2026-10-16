
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

BreachStatus = Literal[
    "ON_TRACK",
    "APPROACHING",
    "BREACHED",
    "RESOLVED",
]

EscalationStatus = Literal[
    "NOT_REQUIRED",
    "PENDING",
    "ESCALATED",
]


class SLAPolicyCreate(BaseModel):
    severity: Severity
    acknowledgment_minutes: int = Field(gt=0, le=10080)
    investigation_minutes: int = Field(gt=0, le=10080)
    resolution_minutes: int = Field(gt=0, le=43200)
    escalation_after_minutes: int = Field(default=15, gt=0, le=10080)
    is_active: bool = True


class SLAPolicyUpdate(BaseModel):
    acknowledgment_minutes: int | None = Field(
        default=None, gt=0, le=10080
    )
    investigation_minutes: int | None = Field(
        default=None, gt=0, le=10080
    )
    resolution_minutes: int | None = Field(
        default=None, gt=0, le=43200
    )
    escalation_after_minutes: int | None = Field(
        default=None, gt=0, le=10080
    )
    is_active: bool | None = None


class SLAPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    severity: str
    acknowledgment_minutes: int
    investigation_minutes: int
    resolution_minutes: int
    escalation_after_minutes: int
    is_active: bool
    created_at: datetime
    updated_at: datetime


class IncidentSLARead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    policy_id: int | None
    severity: str

    started_at: datetime
    acknowledgment_deadline: datetime
    investigation_deadline: datetime
    resolution_deadline: datetime

    acknowledged_at: datetime | None
    investigation_started_at: datetime | None
    resolved_at: datetime | None

    actual_response_minutes: int | None
    actual_investigation_minutes: int | None
    actual_resolution_minutes: int | None

    acknowledgment_breached: bool
    investigation_breached: bool
    resolution_breached: bool
    breach_status: str

    escalation_status: str
    escalated_at: datetime | None

    created_at: datetime
    updated_at: datetime


class SLAEventUpdate(BaseModel):
    event: Literal[
        "ACKNOWLEDGED",
        "INVESTIGATION_STARTED",
        "RESOLVED",
    ]


class SLADeadlineItem(BaseModel):
    incident_id: int
    incident_title: str
    severity: str
    deadline_type: Literal[
        "ACKNOWLEDGMENT",
        "INVESTIGATION",
        "RESOLUTION",
    ]
    deadline: datetime
    minutes_remaining: int
    breach_status: str
    escalation_status: str


class SLASummary(BaseModel):
    total_tracked: int
    on_track: int
    approaching_deadline: int
    breached: int
    resolved: int
    escalation_pending: int
    escalated: int
