
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from database import get_db
from schemas.dashboard import (
    AnalystWorkloadResponse,
    DashboardSummaryResponse,
    IncidentTrendsResponse,
    RemediationDashboardResponse,
    VulnerabilityDashboardResponse,
)
from services.dashboard_service import DashboardService


router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Security Dashboard"],
)


DASHBOARD_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
    "IT_ADMINISTRATOR",
    "AUDITOR",
    "VIEWER",
}


def normalize_role(user) -> str:
    return (
        str(user.role)
        .upper()
        .split(".")[-1]
        .replace(" ", "_")
    )


def require_dashboard_access(user) -> None:
    if normalize_role(user) not in DASHBOARD_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view the dashboard",
        )


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
)
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_dashboard_access(current_user)
    return DashboardService.get_summary(db)


@router.get(
    "/vulnerabilities",
    response_model=VulnerabilityDashboardResponse,
)
def dashboard_vulnerabilities(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_dashboard_access(current_user)
    return DashboardService.get_vulnerabilities(db)


@router.get(
    "/analyst-workload",
    response_model=AnalystWorkloadResponse,
)
def dashboard_analyst_workload(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_dashboard_access(current_user)
    return DashboardService.get_analyst_workload(db)


@router.get(
    "/incident-trends",
    response_model=IncidentTrendsResponse,
)
def dashboard_incident_trends(
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_dashboard_access(current_user)

    try:
        return DashboardService.get_incident_trends(
            db,
            start_date=start_date,
            end_date=end_date,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@router.get(
    "/remediation",
    response_model=RemediationDashboardResponse,
)
def dashboard_remediation(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_dashboard_access(current_user)
    return DashboardService.get_remediation(db)
