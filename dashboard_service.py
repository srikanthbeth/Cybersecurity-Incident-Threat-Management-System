
from datetime import date, timedelta

from sqlalchemy.orm import Session

from repositories.dashboard_repository import DashboardRepository


class DashboardService:
    """Business logic for security dashboard metrics."""

    @staticmethod
    def get_summary(db: Session) -> dict:
        return {
            "total_incidents": (
                DashboardRepository.total_incidents(db)
            ),
            "open_incidents": (
                DashboardRepository.count_incidents_by_status(
                    db,
                    (
                        "NEW",
                        "ASSIGNED",
                        "INVESTIGATING",
                        "CONTAINMENT",
                    ),
                )
            ),
            "resolved_incidents": (
                DashboardRepository.count_incidents_by_status(
                    db,
                    ("RESOLVED", "CLOSED"),
                )
            ),
            "critical_alerts": (
                DashboardRepository.critical_alert_count(db)
            ),
            "vulnerabilities_by_severity": (
                DashboardRepository.vulnerabilities_by_severity(db)
            ),
            "high_risk_assets": (
                DashboardRepository.high_risk_asset_count(db)
            ),
            "average_response_time_hours": (
                DashboardRepository.average_response_time_hours(db)
            ),
            "response_time_basis": (
                "Average time from incident creation to the first "
                "matching assignment, investigation, response, "
                "acknowledgement, or containment history event. "
                "This is a proxy, not a dedicated response timestamp."
            ),
            "sla_compliance_percentage": None,
            "sla_eligible_incidents": 0,
            "sla_note": (
                "Not calculated: incidents do not currently store an "
                "SLA target or deadline. Configure an explicit SLA "
                "policy before reporting compliance."
            ),
            "overdue_remediation_tasks": (
                DashboardRepository.overdue_remediation_count(db)
            ),
        }

    @staticmethod
    def get_vulnerabilities(db: Session) -> dict:
        by_severity = (
            DashboardRepository.vulnerabilities_by_severity(db)
        )

        return {
            "total": sum(by_severity.values()),
            "by_severity": by_severity,
        }

    @staticmethod
    def get_analyst_workload(db: Session) -> dict:
        items = DashboardRepository.analyst_workload(db)

        return {
            "items": items,
            "total_analysts": len(items),
        }

    @staticmethod
    def get_incident_trends(
        db: Session,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> dict:
        end_date = end_date or date.today()
        start_date = start_date or end_date - timedelta(days=29)

        if start_date > end_date:
            raise ValueError(
                "start_date must be on or before end_date"
            )

        if (end_date - start_date).days > 365:
            raise ValueError(
                "Date range cannot exceed 366 calendar days"
            )

        items = DashboardRepository.incident_trends(
            db,
            start_date,
            end_date,
        )

        return {
            "start_date": start_date,
            "end_date": end_date,
            "total_incidents": sum(item["count"] for item in items),
            "items": items,
        }

    @staticmethod
    def get_remediation(db: Session) -> dict:
        return DashboardRepository.remediation_metrics(db)
