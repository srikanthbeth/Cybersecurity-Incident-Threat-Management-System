
from datetime import date
from typing import Any

from pydantic import BaseModel, ConfigDict


class DashboardSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_incidents: int
    open_incidents: int
    resolved_incidents: int
    critical_alerts: int
    vulnerabilities_by_severity: dict[str, int]
    high_risk_assets: int
    average_response_time_hours: float | None
    response_time_basis: str
    sla_compliance_percentage: float | None
    sla_eligible_incidents: int
    sla_note: str
    overdue_remediation_tasks: int


class VulnerabilityDashboardResponse(BaseModel):
    total: int
    by_severity: dict[str, int]


class AnalystWorkloadItem(BaseModel):
    analyst_id: int
    analyst_name: str
    role: str
    active_incidents: int
    active_remediation_tasks: int
    total_active_work: int


class AnalystWorkloadResponse(BaseModel):
    items: list[AnalystWorkloadItem]
    total_analysts: int


class IncidentTrendItem(BaseModel):
    date: date
    count: int


class IncidentTrendsResponse(BaseModel):
    start_date: date
    end_date: date
    total_incidents: int
    items: list[IncidentTrendItem]


class RemediationDashboardResponse(BaseModel):
    total_tasks: int
    overdue_tasks: int
    overdue_by_priority: dict[str, int]
    overdue_by_status: dict[str, int]


class DashboardErrorResponse(BaseModel):
    detail: str


class DashboardDebugResponse(BaseModel):
    details: dict[str, Any]
