
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


StepType = Literal[
    "INVESTIGATION",
    "CONTAINMENT",
    "ERADICATION",
    "RECOVERY",
    "MONITORING",
    "SIMULATED_ACTION",
]


class PlaybookStepCreate(BaseModel):
    step_number: int = Field(ge=1)
    title: str = Field(min_length=3, max_length=150)
    description: str | None = None
    step_type: StepType = "INVESTIGATION"
    requires_approval: bool = False


class PlaybookCreate(BaseModel):
    name: str = Field(min_length=3, max_length=150)
    description: str | None = None
    category: str = Field(default="GENERAL", min_length=2, max_length=50)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    steps: list[PlaybookStepCreate] = Field(min_length=1, max_length=50)

    @model_validator(mode="after")
    def validate_step_numbers(self):
        numbers = [step.step_number for step in self.steps]
        if len(numbers) != len(set(numbers)):
            raise ValueError("Step numbers must be unique")
        return self


class PlaybookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=150)
    description: str | None = None
    category: str | None = Field(default=None, min_length=2, max_length=50)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    is_active: bool | None = None


class PlaybookStepRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    playbook_id: int
    step_number: int
    title: str
    description: str | None
    step_type: str
    requires_approval: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime


class PlaybookRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    category: str
    severity: str
    is_active: bool
    created_by: int
    created_at: datetime
    updated_at: datetime


class ExecutionCreate(BaseModel):
    incident_id: int | None = Field(default=None, gt=0)
    investigation_id: int | None = Field(default=None, gt=0)
    assigned_to: int | None = Field(default=None, gt=0)
    summary: str | None = None

    @model_validator(mode="after")
    def require_related_record(self):
        if self.incident_id is None and self.investigation_id is None:
            raise ValueError(
                "An incident_id or investigation_id is required"
            )
        return self


class ExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    playbook_id: int
    incident_id: int | None
    investigation_id: int | None
    started_by: int
    assigned_to: int | None
    status: str
    summary: str | None
    started_at: datetime
    completed_at: datetime | None
    updated_at: datetime


class ExecutionStepUpdate(BaseModel):
    status: Literal["IN_PROGRESS", "COMPLETED", "SKIPPED"]
    completion_notes: str | None = None


class ExecutionStepAssign(BaseModel):
    assigned_to: int = Field(gt=0)


class StepApproval(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    notes: str | None = None


class ExecutionStepRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    execution_id: int
    playbook_step_id: int | None
    step_number: int
    title: str
    description: str | None
    step_type: str
    assigned_to: int | None
    status: str
    requires_approval: bool
    approval_status: str
    approved_by: int | None
    approval_notes: str | None
    completion_notes: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ResponseHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    execution_id: int
    actor_id: int | None
    action: str
    details: str | None
    created_at: datetime
