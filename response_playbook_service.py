
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.incident import Incident
from models.investigation import Investigation
from models.response_playbook import ResponsePlaybook
from models.response_playbook_step import ResponsePlaybookStep
from models.playbook_execution import PlaybookExecution
from models.playbook_execution_step import PlaybookExecutionStep
from models.response_history import ResponseHistory
from models.user import User
from schemas.response_playbook import (
    ExecutionCreate,
    ExecutionStepAssign,
    ExecutionStepUpdate,
    PlaybookCreate,
    PlaybookUpdate,
    StepApproval,
)


class ResponsePlaybookService:
    @staticmethod
    def _get_or_404(db: Session, model, record_id: int, label: str):
        record = db.get(model, record_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"{label} not found")
        return record

    @staticmethod
    def _record_history(
        db: Session,
        execution_id: int,
        actor_id: int,
        action: str,
        details: str | None = None,
    ):
        db.add(
            ResponseHistory(
                execution_id=execution_id,
                actor_id=actor_id,
                action=action,
                details=details,
            )
        )

    def create_playbook(
        self, db: Session, actor_id: int, payload: PlaybookCreate
    ):
        playbook = ResponsePlaybook(
            name=payload.name,
            description=payload.description,
            category=payload.category.upper(),
            severity=payload.severity,
            created_by=actor_id,
            is_active=True,
        )
        db.add(playbook)
        db.flush()

        for item in payload.steps:
            db.add(
                ResponsePlaybookStep(
                    playbook_id=playbook.id,
                    step_number=item.step_number,
                    title=item.title,
                    description=item.description,
                    step_type=item.step_type,
                    requires_approval=item.requires_approval,
                    is_active=True,
                )
            )

        db.commit()
        db.refresh(playbook)
        return playbook

    def list_playbooks(self, db: Session, active_only: bool = False):
        query = select(ResponsePlaybook).order_by(ResponsePlaybook.id.desc())
        if active_only:
            query = query.where(ResponsePlaybook.is_active.is_(True))
        return list(db.scalars(query).all())

    def get_playbook(self, db: Session, playbook_id: int):
        return self._get_or_404(
            db, ResponsePlaybook, playbook_id, "Playbook"
        )

    def get_playbook_steps(self, db: Session, playbook_id: int):
        self.get_playbook(db, playbook_id)
        query = (
            select(ResponsePlaybookStep)
            .where(
                ResponsePlaybookStep.playbook_id == playbook_id,
                ResponsePlaybookStep.is_active.is_(True),
            )
            .order_by(ResponsePlaybookStep.step_number)
        )
        return list(db.scalars(query).all())

    def update_playbook(
        self,
        db: Session,
        playbook_id: int,
        payload: PlaybookUpdate,
    ):
        playbook = self.get_playbook(db, playbook_id)
        changes = payload.model_dump(exclude_unset=True)

        for key, value in changes.items():
            if key == "category" and value is not None:
                value = value.upper()
            setattr(playbook, key, value)

        db.commit()
        db.refresh(playbook)
        return playbook

    def add_step(self, db: Session, playbook_id: int, payload):
        playbook = self.get_playbook(db, playbook_id)
        if not playbook.is_active:
            raise HTTPException(
                status_code=409, detail="Inactive playbooks cannot be modified"
            )

        duplicate = db.scalar(
            select(ResponsePlaybookStep).where(
                ResponsePlaybookStep.playbook_id == playbook_id,
                ResponsePlaybookStep.step_number == payload.step_number,
            )
        )
        if duplicate:
            raise HTTPException(
                status_code=409, detail="Step number already exists"
            )

        step = ResponsePlaybookStep(
            playbook_id=playbook_id,
            step_number=payload.step_number,
            title=payload.title,
            description=payload.description,
            step_type=payload.step_type,
            requires_approval=payload.requires_approval,
            is_active=True,
        )
        db.add(step)
        db.commit()
        db.refresh(step)
        return step

    def start_execution(
        self,
        db: Session,
        actor_id: int,
        playbook_id: int,
        payload: ExecutionCreate,
    ):
        playbook = self.get_playbook(db, playbook_id)
        if not playbook.is_active:
            raise HTTPException(
                status_code=409, detail="Playbook is inactive"
            )

        if payload.incident_id is not None:
            self._get_or_404(
                db, Incident, payload.incident_id, "Incident"
            )

        if payload.investigation_id is not None:
            self._get_or_404(
                db, Investigation, payload.investigation_id, "Investigation"
            )

        steps = self.get_playbook_steps(db, playbook_id)
        if not steps:
            raise HTTPException(
                status_code=409, detail="Playbook has no active steps"
            )

        if payload.assigned_to is not None:
            assignee = self._get_or_404(
                db, User, payload.assigned_to, "Assigned user"
            )
            if not assignee.is_active:
                raise HTTPException(
                    status_code=400, detail="Assigned user is inactive"
                )

        execution = PlaybookExecution(
            playbook_id=playbook_id,
            incident_id=payload.incident_id,
            investigation_id=payload.investigation_id,
            started_by=actor_id,
            assigned_to=payload.assigned_to,
            summary=payload.summary,
            status="IN_PROGRESS",
        )
        db.add(execution)
        db.flush()

        for step in steps:
            db.add(
                PlaybookExecutionStep(
                    execution_id=execution.id,
                    playbook_step_id=step.id,
                    step_number=step.step_number,
                    title=step.title,
                    description=step.description,
                    step_type=step.step_type,
                    status="PENDING",
                    requires_approval=step.requires_approval,
                    approval_status=(
                        "PENDING" if step.requires_approval else "NOT_REQUIRED"
                    ),
                )
            )

        self._record_history(
            db,
            execution.id,
            actor_id,
            "EXECUTION_STARTED",
            f"Started playbook: {playbook.name}",
        )
        db.commit()
        db.refresh(execution)
        return execution

    def get_execution(self, db: Session, execution_id: int):
        return self._get_or_404(
            db, PlaybookExecution, execution_id, "Execution"
        )

    def list_execution_steps(self, db: Session, execution_id: int):
        self.get_execution(db, execution_id)
        query = (
            select(PlaybookExecutionStep)
            .where(PlaybookExecutionStep.execution_id == execution_id)
            .order_by(PlaybookExecutionStep.step_number)
        )
        return list(db.scalars(query).all())

    def assign_step(
        self,
        db: Session,
        actor_id: int,
        execution_id: int,
        step_id: int,
        payload: ExecutionStepAssign,
    ):
        self.get_execution(db, execution_id)
        step = self._get_or_404(
            db, PlaybookExecutionStep, step_id, "Execution step"
        )
        if step.execution_id != execution_id:
            raise HTTPException(
                status_code=404, detail="Execution step not found"
            )
        if step.status in ("COMPLETED", "SKIPPED"):
            raise HTTPException(
                status_code=409, detail="Finished steps cannot be reassigned"
            )

        user = self._get_or_404(
            db, User, payload.assigned_to, "Assigned user"
        )
        if not user.is_active:
            raise HTTPException(
                status_code=400, detail="Assigned user is inactive"
            )

        step.assigned_to = user.id
        self._record_history(
            db,
            execution_id,
            actor_id,
            "STEP_ASSIGNED",
            f"Step {step.step_number} assigned to user {user.id}",
        )
        db.commit()
        db.refresh(step)
        return step

    def approve_step(
        self,
        db: Session,
        actor_id: int,
        execution_id: int,
        step_id: int,
        payload: StepApproval,
    ):
        self.get_execution(db, execution_id)
        step = self._get_or_404(
            db, PlaybookExecutionStep, step_id, "Execution step"
        )
        if step.execution_id != execution_id:
            raise HTTPException(
                status_code=404, detail="Execution step not found"
            )
        if not step.requires_approval:
            raise HTTPException(
                status_code=400, detail="This step does not require approval"
            )
        if step.status in ("COMPLETED", "SKIPPED"):
            raise HTTPException(
                status_code=409, detail="Finished steps cannot be approved"
            )

        step.approval_status = payload.decision
        step.approved_by = actor_id
        step.approval_notes = payload.notes

        self._record_history(
            db,
            execution_id,
            actor_id,
            f"STEP_{payload.decision}",
            f"Step {step.step_number}: {payload.notes or 'No notes'}",
        )
        db.commit()
        db.refresh(step)
        return step

    def update_execution_step(
        self,
        db: Session,
        actor_id: int,
        execution_id: int,
        step_id: int,
        payload: ExecutionStepUpdate,
    ):
        execution = self.get_execution(db, execution_id)
        if execution.status != "IN_PROGRESS":
            raise HTTPException(
                status_code=409, detail="Execution is not in progress"
            )

        step = self._get_or_404(
            db, PlaybookExecutionStep, step_id, "Execution step"
        )
        if step.execution_id != execution_id:
            raise HTTPException(
                status_code=404, detail="Execution step not found"
            )
        if step.status in ("COMPLETED", "SKIPPED"):
            raise HTTPException(
                status_code=409, detail="Finished steps cannot be modified"
            )

        if payload.status == "COMPLETED":
            if (
                step.requires_approval
                and step.approval_status != "APPROVED"
            ):
                raise HTTPException(
                    status_code=403,
                    detail="This step requires approval before completion",
                )

        now = datetime.now(timezone.utc)
        if payload.status == "IN_PROGRESS" and step.started_at is None:
            step.started_at = now

        if payload.status in ("COMPLETED", "SKIPPED"):
            step.completed_at = now

        step.status = payload.status
        step.completion_notes = payload.completion_notes

        self._record_history(
            db,
            execution_id,
            actor_id,
            f"STEP_{payload.status}",
            f"Step {step.step_number}: {payload.completion_notes or 'No notes'}",
        )

        db.flush()
        steps = self.list_execution_steps(db, execution_id)
        if steps and all(
            item.status in ("COMPLETED", "SKIPPED") for item in steps
        ):
            execution.status = "COMPLETED"
            execution.completed_at = now
            self._record_history(
                db,
                execution_id,
                actor_id,
                "EXECUTION_COMPLETED",
                "All execution steps are finished",
            )

        db.commit()
        db.refresh(step)
        return step

    def list_history(self, db: Session, execution_id: int):
        self.get_execution(db, execution_id)
        query = (
            select(ResponseHistory)
            .where(ResponseHistory.execution_id == execution_id)
            .order_by(ResponseHistory.created_at, ResponseHistory.id)
        )
        return list(db.scalars(query).all())


response_playbook_service = ResponsePlaybookService()
