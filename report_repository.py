from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from models.alert import Alert
from models.asset import Asset
from models.incident import Incident
from models.remediation_task import RemediationTask
from models.risk_assessment import RiskAssessment
from models.user import User
from models.vulnerability import Vulnerability


class ReportRepository:
    def __init__(self, db: Session):
        self.db = db

    def incidents_between(self, start: datetime, end: datetime):
        return (
            self.db.query(Incident)
            .filter(
                Incident.created_at >= start,
                Incident.created_at < end,
            )
            .order_by(Incident.created_at.asc())
            .all()
        )

    def alerts_between(self, start: datetime, end: datetime):
        return (
            self.db.query(Alert)
            .filter(
                Alert.created_at >= start,
                Alert.created_at < end,
            )
            .order_by(Alert.created_at.asc())
            .all()
        )

    def vulnerabilities_all(self):
        return (
            self.db.query(Vulnerability)
            .order_by(Vulnerability.severity.asc(), Vulnerability.id.asc())
            .all()
        )

    def vulnerability_groups(self):
        rows = (
            self.db.query(
                Vulnerability.severity,
                Vulnerability.status,
                func.count(Vulnerability.id),
            )
            .group_by(Vulnerability.severity, Vulnerability.status)
            .all()
        )

        return [
            {
                "severity": str(severity.value if hasattr(severity, "value") else severity),
                "status": str(status.value if hasattr(status, "value") else status),
                "count": count,
            }
            for severity, status, count in rows
        ]

    def asset_risk_assessments(self):
        return (
            self.db.query(RiskAssessment, Asset)
            .join(Asset, RiskAssessment.asset_id == Asset.id)
            .order_by(RiskAssessment.risk_score.desc())
            .all()
        )

    def analyst_users(self):
        return (
            self.db.query(User)
            .filter(
                User.is_active.is_(True),
                User.role.in_(
                    [
                        "SECURITY_ANALYST",
                        "INCIDENT_RESPONDER",
                    ]
                ),
            )
            .order_by(User.full_name.asc())
            .all()
        )

    def incident_counts_by_assignee(self):
        rows = (
            self.db.query(
                Incident.assigned_to,
                Incident.status,
                func.count(Incident.id),
            )
            .filter(Incident.assigned_to.is_not(None))
            .group_by(Incident.assigned_to, Incident.status)
            .all()
        )

        return rows

    def remediation_counts_by_assignee(self):
        rows = (
            self.db.query(
                RemediationTask.assigned_to,
                RemediationTask.status,
                func.count(RemediationTask.id),
            )
            .filter(RemediationTask.assigned_to.is_not(None))
            .group_by(RemediationTask.assigned_to, RemediationTask.status)
            .all()
        )

        return rows

    def remediation_tasks_all(self):
        return (
            self.db.query(RemediationTask)
            .order_by(RemediationTask.due_at.asc().nullslast())
            .all()
        )

    def resolved_incidents_between(self, start: datetime, end: datetime):
        return (
            self.db.query(Incident)
            .filter(
                Incident.resolved_at.is_not(None),
                Incident.resolved_at >= start,
                Incident.resolved_at < end,
            )
            .order_by(Incident.resolved_at.asc())
            .all()
        )
