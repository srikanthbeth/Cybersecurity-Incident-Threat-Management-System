
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CorrelationGroupCreate(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    description: str | None = None
    rule_type: Literal[
        "MANUAL",
        "SAME_ASSET",
        "SAME_CATEGORY",
    ] = "MANUAL"


class CorrelationGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    rule_type: str
    status: str
    created_by: int
    created_at: datetime
    updated_at: datetime


class CorrelationMemberCreate(BaseModel):
    alert_id: int = Field(gt=0)


class CorrelationMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    alert_id: int
    added_by: int
    created_at: datetime


class IncidentRelationshipCreate(BaseModel):
    target_incident_id: int = Field(gt=0)
    relationship_type: Literal[
        "RELATED",
        "DUPLICATE_OF",
        "CAUSED_BY",
    ] = "RELATED"
    details: str | None = None


class IncidentRelationshipResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_incident_id: int
    target_incident_id: int
    relationship_type: str
    details: str | None
    created_by: int
    created_at: datetime


class DuplicateIncidentMatch(BaseModel):
    incident_id: int
    incident_number: str
    title: str
    category: str
    severity: str
    status: str
    matching_reasons: list[str]


class AlertCorrelationResponse(BaseModel):
    asset_id: int | None
    category: str
    window_minutes: int
    matching_alert_ids: list[int]
    suggested_incident_id: int | None
    reason: str


class CorrelationHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: int
    action: str
    entity_type: str
    entity_id: int
    details: str | None
    created_at: datetime
