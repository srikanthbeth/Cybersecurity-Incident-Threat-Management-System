
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


RemediationPriority = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RemediationStatus = Literal[
    "OPEN",
    "IN_PROGRESS",
    "PENDING_APPROVAL",
    "REJECTED",
    "COMPLETED",
    "CANCELLED",
]

EvidenceType = Literal[
    "NOTE",
    "URL",
    "LOG",
    "SCREENSHOT",
    "REPORT",
    "OTHER",
]


class RemediationTaskCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=5, max_length=10000)

    asset_id: int | None = Field(default=None, gt=0)
    vulnerability_id: int | None = Field(default=None, gt=0)
    incident_id: int | None = Field(default=None, gt=0)

    assigned_team_id: int = Field(gt=0)
    assigned_to: int | None = Field(default=None, gt=0)

    priority: RemediationPriority = "MEDIUM"
    due_at: datetime

    @model_validator(mode="after")
    def validate_related_resource(self):
        if not any(
            value is not None
            for value in (
                self.asset_id,
                self.vulnerability_id,
                self.incident_id,
            )
        ):
            raise ValueError(
                "Provide at least one asset_id, vulnerability_id, "
                "or incident_id"
            )
        return self


class RemediationTaskUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, min_length=5, max_length=10000)
    assigned_team_id: int | None = Field(default=None, gt=0)
    assigned_to: int | None = Field(default=None, gt=0)
    priority: RemediationPriority | None = None
    due_at: datetime | None = None


class RemediationStart(BaseModel):
    details: str = Field(min_length=3, max_length=5000)


class RemediationEvidenceCreate(BaseModel):
    evidence_type: EvidenceType = "NOTE"
    description: str = Field(min_length=3, max_length=10000)
    evidence_url: str | None = Field(default=None, max_length=2048)
    file_name: str | None = Field(default=None, max_length=255)


class RemediationSubmit(BaseModel):
    details: str = Field(min_length=3, max_length=5000)


class RemediationReview(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    comment: str = Field(min_length=3, max_length=5000)


class RemediationCancel(BaseModel):
    reason: str = Field(min_length=3, max_length=5000)


class RemediationTaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    task_number: str
    title: str
    description: str
    asset_id: int | None
    vulnerability_id: int | None
    incident_id: int | None
    assigned_team_id: int
    assigned_to: int | None
    created_by: int
    priority: str
    status: str
    due_at: datetime
    submitted_at: datetime | None
    reviewed_by: int | None
    reviewed_at: datetime | None
    review_comment: str | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class RemediationEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    task_id: int
    submitted_by: int
    evidence_type: str
    description: str
    evidence_url: str | None
    file_name: str | None
    created_at: datetime


class RemediationHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    task_id: int
    actor_id: int
    action: str
    previous_status: str | None
    new_status: str | None
    details: str | None
    created_at: datetime
