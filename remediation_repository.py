
from datetime import datetime, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.asset import Asset
from models.incident import Incident
from models.remediation_evidence import RemediationEvidence
from models.remediation_history import RemediationHistory
from models.remediation_task import RemediationTask
from models.security_team import SecurityTeam, SecurityTeamMember
from models.user import User
from models.vulnerability import Vulnerability


class RemediationRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_task(self, task_id: int):
        return self.db.get(RemediationTask, task_id)

    def get_asset(self, asset_id: int):
        return self.db.get(Asset, asset_id)

    def get_vulnerability(self, vulnerability_id: int):
        return self.db.get(Vulnerability, vulnerability_id)

    def get_incident(self, incident_id: int):
        return self.db.get(Incident, incident_id)

    def get_team(self, team_id: int):
        return self.db.get(SecurityTeam, team_id)

    def get_user(self, user_id: int):
        return self.db.get(User, user_id)

    def is_team_member(self, team_id: int, user_id: int) -> bool:
        return (
            self.db.query(SecurityTeamMember.id)
            .filter(
                SecurityTeamMember.team_id == team_id,
                SecurityTeamMember.user_id == user_id,
            )
            .first()
            is not None
        )

    def create_task(self, task: RemediationTask):
        self.db.add(task)
        self.db.flush()
        return task

    def create_evidence(self, evidence: RemediationEvidence):
        self.db.add(evidence)
        self.db.flush()
        return evidence

    def create_history(self, history: RemediationHistory):
        self.db.add(history)
        self.db.flush()
        return history

    def list_tasks(
        self,
        status: str | None = None,
        priority: str | None = None,
        assigned_team_id: int | None = None,
        assigned_to: int | None = None,
        overdue_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ):
        query = self.db.query(RemediationTask)

        if status:
            query = query.filter(RemediationTask.status == status)
        if priority:
            query = query.filter(RemediationTask.priority == priority)
        if assigned_team_id:
            query = query.filter(
                RemediationTask.assigned_team_id == assigned_team_id
            )
        if assigned_to:
            query = query.filter(RemediationTask.assigned_to == assigned_to)
        if overdue_only:
            now = datetime.now(timezone.utc)
            query = query.filter(
                RemediationTask.due_at < now,
                RemediationTask.status.notin_(["COMPLETED", "CANCELLED"]),
            )

        return (
            query.order_by(RemediationTask.due_at.asc(), RemediationTask.id.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def list_evidence(self, task_id: int):
        return (
            self.db.query(RemediationEvidence)
            .filter(RemediationEvidence.task_id == task_id)
            .order_by(RemediationEvidence.created_at.asc())
            .all()
        )

    def list_history(self, task_id: int):
        return (
            self.db.query(RemediationHistory)
            .filter(RemediationHistory.task_id == task_id)
            .order_by(RemediationHistory.created_at.asc())
            .all()
        )

    def commit(self):
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def rollback(self):
        self.db.rollback()
