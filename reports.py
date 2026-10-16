
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from database import get_db
from services.report_service import ReportService
from utils.csv_export import report_to_csv

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"],
)

MANAGEMENT_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "AUDITOR",
}

REPORT_ROLE_ACCESS = {
    "daily-incidents": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST",
        "INCIDENT_RESPONDER", "IT_ADMINISTRATOR", "AUDITOR", "VIEWER",
    },
    "weekly-security": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST",
        "INCIDENT_RESPONDER", "IT_ADMINISTRATOR", "AUDITOR", "VIEWER",
    },
    "vulnerability-analysis": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST",
        "INCIDENT_RESPONDER", "IT_ADMINISTRATOR", "AUDITOR", "VIEWER",
    },
    "asset-risk": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "IT_ADMINISTRATOR", "AUDITOR",
    },
    "analyst-performance": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "AUDITOR",
    },
    "sla-compliance": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "AUDITOR",
    },
    "remediation-status": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST",
        "INCIDENT_RESPONDER", "IT_ADMINISTRATOR", "AUDITOR",
    },
    "resolution-trends": {
        "SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST",
        "INCIDENT_RESPONDER", "IT_ADMINISTRATOR", "AUDITOR", "VIEWER",
    },
}


def _role_name(user: Any) -> str:
    role = getattr(user, "role", "")
    return str(getattr(role, "value", role)).upper()


def _authorize_report(report_name: str, user: Any) -> None:
    allowed_roles = REPORT_ROLE_ACCESS.get(report_name)

    if allowed_roles is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown report: {report_name}",
        )

    if _role_name(user) not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this report",
        )


def _generate_report(
    report_name: str,
    start_date: date | None,
    end_date: date | None,
    user: Any,
    db: Session,
) -> dict:
    _authorize_report(report_name, user)

    try:
        service = ReportService(db)
        return service.generate(
            report_name=report_name,
            start_date=start_date,
            end_date=end_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _report_parameters(
    start_date: date | None = Query(
        default=None,
        description="Inclusive report start date (YYYY-MM-DD)",
    ),
    end_date: date | None = Query(
        default=None,
        description="Inclusive report end date (YYYY-MM-DD)",
    ),
) -> tuple[date | None, date | None]:
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=422,
            detail="start_date must be on or before end_date",
        )

    return start_date, end_date


@router.get("/daily-incidents", summary="Daily incident summaries")
def daily_incidents_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report("daily-incidents", dates[0], dates[1], user, db)


@router.get("/weekly-security", summary="Weekly security summaries")
def weekly_security_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report("weekly-security", dates[0], dates[1], user, db)


@router.get("/vulnerability-analysis", summary="Vulnerability analysis")
def vulnerability_analysis_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report(
        "vulnerability-analysis", dates[0], dates[1], user, db
    )


@router.get("/asset-risk", summary="Asset risk report")
def asset_risk_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report("asset-risk", dates[0], dates[1], user, db)


@router.get("/analyst-performance", summary="Analyst performance report")
def analyst_performance_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report(
        "analyst-performance", dates[0], dates[1], user, db
    )


@router.get("/sla-compliance", summary="SLA compliance report")
def sla_compliance_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report("sla-compliance", dates[0], dates[1], user, db)


@router.get("/remediation-status", summary="Remediation status report")
def remediation_status_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report(
        "remediation-status", dates[0], dates[1], user, db
    )


@router.get("/resolution-trends", summary="Incident resolution trends")
def resolution_trends_report(
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _generate_report(
        "resolution-trends", dates[0], dates[1], user, db
    )


@router.get("/csv/{report_name}", summary="Export a report as CSV")
def export_report_csv(
    report_name: str,
    dates: tuple[date | None, date | None] = Depends(_report_parameters),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report = _generate_report(
        report_name, dates[0], dates[1], user, db
    )
    return report_to_csv(report, f"{report_name}.csv")
