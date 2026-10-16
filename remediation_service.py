
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.remediation_evidence import RemediationEvidence
from models.remediation_history import RemediationHistory
from models.remediation_task import RemediationTask
from repositories.remediation_repository import RemediationRepository
from schemas.remediation import (
    RemediationEvidenceCreate,
    RemediationReview,
    RemediationTaskCreate,
    RemediationTaskUpdate,
)


ACTIVE_STATUSES = {
    "OPEN",
    "IN_PROGRESS",
    "PENDING_APPROVAL",
    "REJECTED",
}

TERMINAL_STATUSES = {"COMPLETED", "CANCELLED"}


class RemediationService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = RemediationRepository(db)

    @staticmethod
    def now():
        return datetime.now(timezone.utc)

    def _task_or_404(self, task_id: int):
        task = self.repo.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Remediation task not found")
        return task

    def _record_history(
        self,
        task: RemediationTask,
        actor_id: int,
        action: str,
        previous_status: str | None,
        new_status: str | None,
        details: str | None = None,
    ):
        self.repo.create_history(
            RemediationHistory(
                task_id=task.id,
                actor_id=actor_id,
                action=action,
                previous_status=previous_status,
                new_status=new_status,
                details=details,
            )
        )

    def _validate_references(self, payload: RemediationTaskCreate):
        if payload.asset_id and not self.repo.get_asset(payload.asset_id):
            raise HTTPException(status_code=404, detail="Asset not found")

        if payload.vulnerability_id:
            vulnerability = self.repo.get_vulnerability(payload.vulnerability_id)
            if not vulnerability:
                raise HTTPException(
                    status_code=404, detail="Vulnerability not found"
                )

        if payload.incident_id and not self.repo.get_incident(payload.incident_id):
            raise HTTPException(status_code=404, detail="Incident not found")

        team = self.repo.get_team(payload.assigned_team_id)
        if not team or not team.is_active:
            raise HTTPException(
                status_code=400, detail="Assigned team does not exist or is inactive"
            )

        if payload.assigned_to:
            user = self.repo.get_user(payload.assigned_to)
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=400, detail="Assigned user does not exist or is inactive"
                )
            if not self.repo.is_team_member(
                payload.assigned_team_id, payload.assigned_to
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Assigned user must belong to the responsible team",
                )

        if payload.due_at <= self.now():
            raise HTTPException(
                status_code=422, detail="Remediation deadline must be in the future"
            )

    def create(self, payload: RemediationTaskCreate, actor):
        self._validate_references(payload)

        task = RemediationTask(
            task_number=f"RMD-{uuid4().hex[:12].upper()}",
            title=payload.title,
            description=payload.description,
            asset_id=payload.asset_id,
            vulnerability_id=payload.vulnerability_id,
            incident_id=payload.incident_id,
            assigned_team_id=payload.assigned_team_id,
            assigned_to=payload.assigned_to,
            created_by=actor.id,
            priority=payload.priority,
            status="OPEN",
            due_at=payload.due_at,
        )

        try:
            self.repo.create_task(task)
            self._record_history(
                task, actor.id, "CREATED", None, "OPEN",
                "Remediation task created",
            )
            self.repo.commit()
            self.db.refresh(task)
            return task
        except Exception:
            self.repo.rollback()
            raise

    def get(self, task_id: int):
        return self._task_or_404(task_id)

    def list(
        self,
        status: str | None = None,
        priority: str | None = None,
        assigned_team_id: int | None = None,
        assigned_to: int | None = None,
        overdue_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ):
        return self.repo.list_tasks(
            status=status,
            priority=priority,
            assigned_team_id=assigned_team_id,
            assigned_to=assigned_to,
            overdue_only=overdue_only,
            limit=limit,
            offset=offset,
        )

    def update(self, task_id: int, payload: RemediationTaskUpdate, actor):
        task = self._task_or_404(task_id)

        if task.status in TERMINAL_STATUSES | {"PENDING_APPROVAL"}:
            raise HTTPException(
                status_code=409,
                detail="This task cannot be edited in its current status",
            )

        values = payload.model_dump(exclude_unset=True)
        if not values:
            raise HTTPException(status_code=422, detail="No update fields supplied")

        if "assigned_team_id" in values:
            team = self.repo.get_team(values["assigned_team_id"])
            if not team or not team.is_active:
                raise HTTPException(
                    status_code=400, detail="Assigned team does not exist or is inactive"
                )

        new_team_id = values.get("assigned_team_id", task.assigned_team_id)
        if "assigned_to" in values and values["assigned_to"] is not None:
            user = self.repo.get_user(values["assigned_to"])
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=400, detail="Assigned user does not exist or is inactive"
                )
            if not self.repo.is_team_member(new_team_id, user.id):
                raise HTTPException(
                    status_code=400,
                    detail="Assigned user must belong to the responsible team",
                )

        if "due_at" in values:
            if values["due_at"] <= self.now():
                raise HTTPException(
                    status_code=422,
                    detail="Remediation deadline must be in the future",
                )

        try:
            for field, value in values.items():
                setattr(task, field, value)

            self._record_history(
                task, actor.id, "UPDATED", task.status, task.status,
                "Updated fields: " + ", ".join(values.keys()),
            )
            self.repo.commit()
            self.db.refresh(task)
            return task
        except Exception:
            self.repo.rollback()
            raise

    def start(self, task_id: int, details: str, actor):
        task = self._task_or_404(task_id)

        if task.status not in {"OPEN", "REJECTED"}:
            raise HTTPException(
                status_code=409,
                detail="Only OPEN or REJECTED tasks can be started",
            )

        previous = task.status
        task.status = "IN_PROGRESS"
        task.review_comment = None

        try:
            self._record_history(
                task, actor.id, "STARTED", previous, task.status, details
            )
            self.repo.commit()
            self.db.refresh(task)
            return task
        except Exception:
            self.repo.rollback()
            raise

    def add_evidence(
        self,
        task_id: int,
        payload: RemediationEvidenceCreate,
        actor,
    ):
        task = self._task_or_404(task_id)

        if task.status != "IN_PROGRESS":
            raise HTTPException(
                status_code=409,
                detail="Evidence can only be added to IN_PROGRESS tasks",
            )

        if payload.evidence_type == "URL" and not payload.evidence_url:
            raise HTTPException(
                status_code=422,
                detail="evidence_url is required for URL evidence",
            )

        evidence = RemediationEvidence(
            task_id=task.id,
            submitted_by=actor.id,
            evidence_type=payload.evidence_type,
            description=payload.description,
            evidence_url=payload.evidence_url,
            file_name=payload.file_name,
        )

        try:
            self.repo.create_evidence(evidence)
            self._record_history(
                task,
                actor.id,
                "EVIDENCE_ADDED",
                task.status,
                task.status,
                payload.description,
            )
            self.repo.commit()
            self.db.refresh(evidence)
            return evidence
        except Exception:
            self.repo.rollback()
            raise

    def list_evidence(self, task_id: int):
        self._task_or_404(task_id)
        return self.repo.list_evidence(task_id)

    def submit(self, task_id: int, details: str, actor):
        task = self._task_or_404(task_id)

        if task.status != "IN_PROGRESS":
            raise HTTPException(
                status_code=409,
                detail="Only IN_PROGRESS tasks can be submitted for approval",
            )

        if not self.repo.list_evidence(task.id):
            raise HTTPException(
                status_code=422,
                detail="At least one remediation evidence record is required",
            )

        previous = task.status
        task.status = "PENDING_APPROVAL"
        task.submitted_at = self.now()
        task.reviewed_by = None
        task.reviewed_at = None
        task.review_comment = None

        try:
            self._record_history(
                task, actor.id, "SUBMITTED_FOR_APPROVAL",
                previous, task.status, details,
            )
            self.repo.commit()
            self.db.refresh(task)
            return task
        except Exception:
            self.repo.rollback()
            raise

    def review(
        self,
        task_id: int,
        payload: RemediationReview,
        actor,
    ):
        task = self._task_or_404(task_id)

        if task.status != "PENDING_APPROVAL":
            raise HTTPException(
                status_code=409,
                detail="Only tasks pending approval can be reviewed",
            )

        if task.created_by == actor.id:
            raise HTTPException(
                status_code=403,
                detail="The task creator cannot approve their own remediation",
            )

        previous = task.status
        task.reviewed_by = actor.id
        task.reviewed_at = self.now()
        task.review_comment = payload.comment

        if payload.decision == "APPROVE":
            task.status = "COMPLETED"
            task.completed_at = self.now()
            action = "APPROVED"
        else:
            task.status = "REJECTED"
            task.completed_at = None
            action = "REJECTED"

        try:
            self._record_history(
                task, actor.id, action, previous, task.status, payload.comment
            )
            self.repo.commit()
            self.db.refresh(task)
            return task
        except Exception:
            self.repo.rollback()
            raise

    def cancel(self, task_id: int, reason: str, actor):
        task = self._task_or_404(task_id)

        if task.status in TERMINAL_STATUSES:
            raise HTTPException(
                status_code=409, detail="Task is already in a terminal status"
            )

        previous = task.status
        task.status = "CANCELLED"

        try:
            self._record_history(
                task, actor.id, "CANCELLED", previous, task.status, reason
            )
            self.repo.commit()
            self.db.refresh(task)
            return task
        except Exception:
            self.repo.rollback()
            raise

    def history(self, task_id: int):
        self._task_or_404(task_id)
        return self.repo.list_history(task_id)
