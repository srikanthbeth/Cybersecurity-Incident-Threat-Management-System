
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AdvancedSearchFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: str | None = None
    severity: str | None = None
    status: str | None = None
    asset_id: int | None = Field(default=None, gt=0)
    analyst_id: int | None = Field(default=None, gt=0)
    organization_name: str | None = None
    incident_number: str | None = None
    start_date: date | None = None
    end_date: date | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
    sort_by: Literal[
        "created_at", "severity", "status", "title", "reference"
    ] = "created_at"
    sort_order: Literal["asc", "desc"] = "desc"
