
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from typing import Annotated


TeamCode = Annotated[
    str,
    StringConstraints(
        min_length=2,
        max_length=50,
        pattern=r"^[A-Za-z0-9_-]+$",
        strip_whitespace=True,
    ),
]


class SecurityTeamCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    code: TeamCode
    description: str | None = Field(default=None, max_length=2000)


class SecurityTeamUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    is_active: bool | None = None


class SecurityTeamResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    code: str
    description: str | None
    is_active: bool
    created_by: int | None
    created_at: datetime
    updated_at: datetime


class SecurityTeamMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    team_id: int
    user_id: int
    assigned_by: int | None
    assigned_at: datetime


class AnalystAssignmentRequest(BaseModel):
    user_id: int = Field(gt=0)
