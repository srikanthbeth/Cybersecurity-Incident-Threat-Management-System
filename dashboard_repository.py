
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from models.alert import Alert
from models.asset import Asset
from models.incident import Incident
from models.incident_history import IncidentHistory
from models.remediation_task import RemediationTask
from models.risk_assessment import RiskAssessment
from models.user import User
from models.vulnerability import Vulnerability


OPEN_INCIDENT_STATUSES = (
    "NEW",
    "ASSIGNED",
    "INVESTIGATING",
    "CONTAINMENT",
)

RESOLVED_INCIDENT_STATUSES = ("RESOLVED", "CLOSED")

ACTIVE_REMEDIATION_STATUSES = (
    "OPEN",
    "IN_PROGRESS",
    "PENDING_APPROVAL",
    "REJECTED",
)

TERMINAL_REMEDIATION_STATUSES = ("COMPLETED", "CANCELLED")

ANALYST_ROLES = (
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
)


class DashboardRepository:
    """Database-backed dashboard calculations."""

    @staticmethod
    def total_incidents(db: Session) -> int:
        return db.scalar(
            select(func.count(Incident.id))
        ) or 0

    @staticmethod
    def count_incidents_by_status(
        db: Session,
        statuses: tuple[str, ...],
    ) -> int:
        return db.scalar(
            select(func.count(Incident.id)).where(
                func.upper(Incident.status).in_(statuses)
            )
        ) or 0

    @staticmethod
    def critical_alert_count(db: Session) -> int:
        return db.scalar(
            select(func.count(Alert.id)).where(
                func.upper(Alert.severity) == "CRITICAL"
            )
        ) or 0

    @staticmethod
    def vulnerabilities_by_severity(db: Session) -> dict[str, int]:
        rows = db.execute(
            select(
                func.upper(Vulnerability.severity),
                func.count(Vulnerability.id),
            ).group_by(func.upper(Vulnerability.severity))
        ).all()

        result = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "OTHER": 0,
        }

        for severity, count in rows:
            key = severity if severity in result else "OTHER"
            result[key] += count

        return result

    @staticmethod
    def high_risk_asset_count(db: Session) -> int:
        assessed_asset_ids = select(
            RiskAssessment.asset_id
        ).where(
            func.upper(RiskAssessment.risk_level).in_(
                ("HIGH", "CRITICAL")
            )
        )

        statement = select(
            func.count(func.distinct(Asset.id))
        ).where(
            or_(
                func.upper(Asset.criticality).in_(
                    ("HIGH", "CRITICAL")
                ),
                Asset.id.in_(assessed_asset_ids),
            )
        )

        return db.scalar(statement) or 0

    @staticmethod
    def overdue_remediation_count(
        db: Session,
        now: datetime | None = None,
    ) -> int:
        now = now or datetime.now(timezone.utc)

        return db.scalar(
            select(func.count(RemediationTask.id)).where(
                RemediationTask.due_at < now,
                func.upper(RemediationTask.status).notin_(
                    TERMINAL_REMEDIATION_STATUSES
                ),
            )
        ) or 0

    @staticmethod
    def remediation_metrics(
        db: Session,
        now: datetime | None = None,
    ) -> dict:
        now = now or datetime.now(timezone.utc)

        total = db.scalar(
            select(func.count(RemediationTask.id))
        ) or 0

        overdue_query = select(RemediationTask).where(
            RemediationTask.due_at < now,
            func.upper(RemediationTask.status).notin_(
                TERMINAL_REMEDIATION_STATUSES
            ),
        )

        overdue_tasks = list(db.scalars(overdue_query).all())

        by_priority = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "OTHER": 0,
        }
        by_status: dict[str, int] = {}

        for task in overdue_tasks:
            priority = str(task.priority).upper()
            if priority not in by_priority:
                priority = "OTHER"
            by_priority[priority] += 1

            status = str(task.status).upper()
            by_status[status] = by_status.get(status, 0) + 1

        return {
            "total_tasks": total,
            "overdue_tasks": len(overdue_tasks),
            "overdue_by_priority": by_priority,
            "overdue_by_status": by_status,
        }

    @staticmethod
    def average_response_time_hours(
        db: Session,
    ) -> float | None:
        """
        Use the first incident-history event that appears to represent
        an assignment or investigation/response action.

        This is a proxy until the application records a dedicated
        first_response_at timestamp.
        """
        incidents = list(
            db.scalars(select(Incident)).all()
        )

        if not incidents:
            return None

        incident_ids = [incident.id for incident in incidents]

        history_rows = db.scalars(
            select(IncidentHistory).where(
                IncidentHistory.incident_id.in_(incident_ids)
            ).order_by(
                IncidentHistory.incident_id.asc(),
                IncidentHistory.created_at.asc(),
                IncidentHistory.id.asc(),
            )
        ).all()

        incident_by_id = {
            incident.id: incident
            for incident in incidents
        }

        response_actions = (
            "ASSIGN",
            "INVESTIGAT",
            "RESPOND",
            "ACKNOWLEDG",
            "CONTAIN",
        )

        first_response_by_incident: dict[int, datetime] = {}

        for history in history_rows:
            action = str(history.action).upper()

            if not any(
                marker in action for marker in response_actions
            ):
                continue

            incident = incident_by_id.get(history.incident_id)
            if incident is None:
                continue

            if history.created_at < incident.created_at:
                continue

            first_response_by_incident.setdefault(
                incident.id,
                history.created_at,
            )

        durations = []

        for incident_id, response_at in first_response_by_incident.items():
            incident = incident_by_id[incident_id]
            delta = response_at - incident.created_at
            durations.append(delta.total_seconds() / 3600)

        if not durations:
            return None

        return round(sum(durations) / len(durations), 2)

    @staticmethod
    def analyst_workload(db: Session) -> list[dict]:
        users = db.scalars(
            select(User).where(
                User.is_active.is_(True),
                func.upper(User.role).in_(ANALYST_ROLES),
            ).order_by(User.full_name.asc(), User.id.asc())
        ).all()

        results = []

        for user in users:
            active_incidents = db.scalar(
                select(func.count(Incident.id)).where(
                    Incident.assigned_to == user.id,
                    func.upper(Incident.status).notin_(
                        RESOLVED_INCIDENT_STATUSES
                    ),
                )
            ) or 0

            active_tasks = db.scalar(
                select(func.count(RemediationTask.id)).where(
                    RemediationTask.assigned_to == user.id,
                    func.upper(RemediationTask.status).notin_(
                        TERMINAL_REMEDIATION_STATUSES
                    ),
                )
            ) or 0

            results.append(
                {
                    "analyst_id": user.id,
                    "analyst_name": user.full_name,
                    "role": str(user.role),
                    "active_incidents": active_incidents,
                    "active_remediation_tasks": active_tasks,
                    "total_active_work": active_incidents + active_tasks,
                }
            )

        return results

    @staticmethod
    def incident_trends(
        db: Session,
        start_date: date,
        end_date: date,
    ) -> list[dict]:
        start_at = datetime.combine(
            start_date,
            time.min,
            tzinfo=timezone.utc,
        )
        end_at = datetime.combine(
            end_date + timedelta(days=1),
            time.min,
            tzinfo=timezone.utc,
        )

        rows = db.execute(
            select(
                func.date(Incident.created_at),
                func.count(Incident.id),
            ).where(
                Incident.created_at >= start_at,
                Incident.created_at < end_at,
            ).group_by(
                func.date(Incident.created_at)
            ).order_by(
                func.date(Incident.created_at)
            )
        ).all()

        counts = {row_date: count for row_date, count in rows}

        results = []
        current = start_date

        while current <= end_date:
            results.append(
                {
                    "date": current,
                    "count": counts.get(current, 0),
                }
            )
            current += timedelta(days=1)

        return results
