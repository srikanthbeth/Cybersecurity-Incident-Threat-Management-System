from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RiskStatus = Literal[
    "OPEN",
    "ACCEPTED",
    "IN_REMEDIATION",
    "REMEDIATED",
]


class RiskDecisionUpdate(BaseModel):
    status: RiskStatus
    details: str | None = Field(default=None, max_length=5000)


class RiskAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    highest_risk_vulnerability_id: int | None
    assessed_by: int
    asset_criticality: str
    vulnerability_severity: str | None
    risk_score: float
    risk_level: str
    status: str
    assessment_details: str
    accepted_reason: str | None
    accepted_by: int | None
    accepted_at: datetime | None
    remediation_notes: str | None
    remediated_by: int | None
    remediated_at: datetime | None
    created_at: datetime


class RiskAssessmentHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    actor_id: int
    action: str
    previous_score: float | None
    new_score: float | None
    previous_level: str | None
    new_level: str | None
    details: str | None
    created_at: datetime