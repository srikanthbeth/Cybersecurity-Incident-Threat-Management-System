from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy.orm import Session

from repositories.report_repository import ReportRepository


OPEN_INCIDENT_STATUSES = {"NEW", "ASSIGNED", "INVESTIGATING", "CONTAINMENT"}
RESOLVED_INCIDENT_STATUSES = {"RESOLVED", "CLOSED"}
TERMINAL_REMEDIATION_STATUSES = {"COMPLETED", "CANCELLED"}


def _value(value):
    return value.value if hasattr(value, "value") else value


def _iso(value):
    return value.isoformat() if value is not None else None


def _date_bounds(
    start_date: date | None,
    end_date: date | None,
    default_days: int = 7,
):
    today = date.today()

    if start_date is None and end_date is None:
        end_date = today
        start_date = today - timedelta(days=default_days - 1)
    elif start_date is None:
        start_date = end_date - timedelta(days=default_days - 1)
    elif end_date is None:
        end_date = start_date + timedelta(days=default_days - 1)

    if start_date > end_date:
        raise ValueError("start_date must be on or before end_date")

    if (end_date - start_date).days > 366:
        raise ValueError("Report date range cannot exceed 366 days")

    start = datetime.combine(start_date, time.min)
    end = datetime.combine(end_date + timedelta(days=1), time.min)

    return start_date, end_date, start, end


class ReportService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = ReportRepository(db)

    def daily_incident_summary(
        self,
        start_date: date | None = None,
        end_date: date | None = None,
    ):
        start_date, end_date, start, end = _date_bounds(
            start_date, end_date, default_days=1
        )
        incidents = self.repo.incidents_between(start, end)

        by_severity = Counter(str(_value(item.severity)) for item in incidents)
        by_status = Counter(str(_value(item.status)) for item in incidents)
        by_day = Counter(item.created_at.date().isoformat() for item in incidents)

        return {
            "report": "daily_incident_summary",
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "total_incidents": len(incidents),
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
            "items": [
                {
                    "incident_id": item.id,
                    "incident_number": item.incident_number,
                    "title": item.title,
                    "severity": _value(item.severity),
                    "status": _value(item.status),
                    "assigned_to": item.assigned_to,
                    "created_at": _iso(item.created_at),
                    "resolved_at": _iso(item.resolved_at),
                }
                for item in incidents
            ],
            "daily_counts": [
                {"date": key, "count": by_day[key]}
                for key in sorted(by_day)
            ],
        }

    def weekly_security_summary(
        self,
        start_date: date | None = None,
        end_date: date | None = None,
    ):
        start_date, end_date, start, end = _date_bounds(
            start_date, end_date, default_days=7
        )
        incidents = self.repo.incidents_between(start, end)
        alerts = self.repo.alerts_between(start, end)

        vulnerabilities = self.repo.vulnerabilities_all()
        vulnerability_counts = Counter(
            str(_value(item.severity)) for item in vulnerabilities
        )

        critical_alerts = sum(
            1 for item in alerts if str(_value(item.severity)) == "CRITICAL"
        )

        return {
            "report": "weekly_security_summary",
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "incidents_created": len(incidents),
            "incidents_open": sum(
                1 for item in incidents
                if str(_value(item.status)) in OPEN_INCIDENT_STATUSES
            ),
            "incidents_resolved": sum(
                1 for item in incidents
                if str(_value(item.status)) in RESOLVED_INCIDENT_STATUSES
            ),
            "alerts_created": len(alerts),
            "critical_alerts_created": critical_alerts,
            "vulnerabilities_by_severity": dict(vulnerability_counts),
            "items": [
                {
                    "metric": "incidents_created",
                    "value": len(incidents),
                },
                {
                    "metric": "critical_alerts_created",
                    "value": critical_alerts,
                },
                {
                    "metric": "vulnerabilities_total",
                    "value": len(vulnerabilities),
                },
            ],
        }

    def vulnerability_analysis(self):
        groups = self.repo.vulnerability_groups()
        vulnerabilities = self.repo.vulnerabilities_all()

        return {
            "report": "vulnerability_analysis",
            "total_vulnerabilities": len(vulnerabilities),
            "groups": groups,
            "items": [
                {
                    "vulnerability_id": item.id,
                    "reference": getattr(item, "vulnerability_ref", None),
                    "title": item.title,
                    "severity": _value(item.severity),
                    "status": _value(item.status),
                    "cvss_score": getattr(item, "cvss_score", None),
                    "created_at": _iso(getattr(item, "created_at", None)),
                }
                for item in vulnerabilities
            ],
        }

    def asset_risk_report(self):
        assessments = self.repo.asset_risk_assessments()

        items = [
            {
                "assessment_id": assessment.id,
                "asset_id": asset.id,
                "asset_tag": asset.asset_tag,
                "asset_name": asset.name,
                "criticality": _value(asset.criticality),
                "risk_level": _value(assessment.risk_level),
                "risk_score": assessment.risk_score,
                "assessment_created_at": _iso(
                    getattr(assessment, "created_at", None)
                ),
            }
            for assessment, asset in assessments
        ]

        return {
            "report": "asset_risk_report",
            "total_assessments": len(items),
            "high_or_critical_assets": sum(
                1 for item in items
                if str(item["risk_level"]) in {"HIGH", "CRITICAL"}
            ),
            "items": items,
        }

    def analyst_performance(self):
        analysts = self.repo.analyst_users()
        incident_rows = self.repo.incident_counts_by_assignee()
        remediation_rows = self.repo.remediation_counts_by_assignee()

        incident_counts = defaultdict(Counter)
        remediation_counts = defaultdict(Counter)

        for user_id, status, count in incident_rows:
            incident_counts[user_id][str(_value(status))] += count

        for user_id, status, count in remediation_rows:
            remediation_counts[user_id][str(_value(status))] += count

        items = []

        for analyst in analysts:
            incidents = incident_counts[analyst.id]
            tasks = remediation_counts[analyst.id]

            items.append(
                {
                    "analyst_id": analyst.id,
                    "analyst_name": analyst.full_name,
                    "email": analyst.email,
                    "assigned_incidents": sum(incidents.values()),
                    "resolved_incidents": sum(
                        incidents[status]
                        for status in RESOLVED_INCIDENT_STATUSES
                    ),
                    "open_incidents": sum(
                        incidents[status]
                        for status in OPEN_INCIDENT_STATUSES
                    ),
                    "assigned_remediation_tasks": sum(tasks.values()),
                    "completed_remediation_tasks": tasks["COMPLETED"],
                }
            )

        return {
            "report": "analyst_performance",
            "analyst_count": len(items),
            "items": items,
        }

    def sla_compliance(self):
        return {
            "report": "sla_compliance",
            "available": False,
            "eligible_incidents": None,
            "compliant_incidents": None,
            "breached_incidents": None,
            "compliance_percentage": None,
            "reason": (
                "SLA compliance cannot be calculated reliably until the "
                "application stores and tracks actual SLA deadlines and outcomes."
            ),
            "items": [],
        }

    def remediation_status(self):
        tasks = self.repo.remediation_tasks_all()
        now = datetime.now()

        by_status = Counter(str(_value(item.status)) for item in tasks)
        by_priority = Counter(str(_value(item.priority)) for item in tasks)

        items = []
        overdue_count = 0

        for task in tasks:
            status = str(_value(task.status))
            due_at = task.due_at
            overdue = (
                due_at is not None
                and due_at < now
                and status not in TERMINAL_REMEDIATION_STATUSES
            )
            overdue_count += int(overdue)

            items.append(
                {
                    "task_id": task.id,
                    "task_number": task.task_number,
                    "title": task.title,
                    "status": status,
                    "priority": _value(task.priority),
                    "assigned_team_id": task.assigned_team_id,
                    "assigned_to": task.assigned_to,
                    "due_at": _iso(due_at),
                    "overdue": overdue,
                }
            )

        return {
            "report": "remediation_status",
            "total_tasks": len(tasks),
            "overdue_tasks": overdue_count,
            "by_status": dict(by_status),
            "by_priority": dict(by_priority),
            "items": items,
        }

    def incident_resolution_trends(
        self,
        start_date: date | None = None,
        end_date: date | None = None,
    ):
        start_date, end_date, start, end = _date_bounds(
            start_date, end_date, default_days=30
        )
        incidents = self.repo.resolved_incidents_between(start, end)

        by_day = Counter(
            item.resolved_at.date().isoformat() for item in incidents
        )

        items = []
        current_day = start_date

        while current_day <= end_date:
            key = current_day.isoformat()
            items.append(
                {
                    "date": key,
                    "resolved_count": by_day.get(key, 0),
                }
            )
            current_day += timedelta(days=1)

        return {
            "report": "incident_resolution_trends",
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "total_resolved": len(incidents),
            "items": items,
        }

    def generate(
        self,
        report_name: str,
        start_date: date | None = None,
        end_date: date | None = None,
    ):
        reports = {
            "daily-incidents": self.daily_incident_summary,
            "weekly-security": self.weekly_security_summary,
            "vulnerability-analysis": self.vulnerability_analysis,
            "asset-risk": self.asset_risk_report,
            "analyst-performance": self.analyst_performance,
            "sla-compliance": self.sla_compliance,
            "remediation-status": self.remediation_status,
            "resolution-trends": self.incident_resolution_trends,
        }

        handler = reports.get(report_name)
        if handler is None:
            return None

        if report_name in {
            "daily-incidents",
            "weekly-security",
            "resolution-trends",
        }:
            return handler(start_date, end_date)

        return handler()
