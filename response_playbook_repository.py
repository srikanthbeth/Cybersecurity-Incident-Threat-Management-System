
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.response_playbook import ResponsePlaybook
from models.response_playbook_step import ResponsePlaybookStep
from models.playbook_execution import PlaybookExecution
from models.playbook_execution_step import PlaybookExecutionStep
from models.response_history import ResponseHistory


class ResponsePlaybookRepository:
    def create_playbook(self, db: Session, playbook: ResponsePlaybook):
        db.add(playbook)
        db.flush()
        return playbook

    def get_playbook(self, db: Session, playbook_id: int):
        return db.get(ResponsePlaybook, playbook_id)

    def list_playbooks(
        self,
        db: Session,
        active_only: bool = False,
        skip: int = 0,
        limit: int = 100,
    ):
        query = select(ResponsePlaybook)

        if active_only:
            query = query.where(ResponsePlaybook.is_active.is_(True))

        query = (
            query.order_by(ResponsePlaybook.id.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(db.scalars(query).all())

    def update_playbook(
        self,
        db: Session,
        playbook: ResponsePlaybook,
        changes: dict,
    ):
        for key, value in changes.items():
            setattr(playbook, key, value)

        db.flush()
        return playbook

    def create_step(self, db: Session, step: ResponsePlaybookStep):
        db.add(step)
        db.flush()
        return step

    def get_step(self, db: Session, step_id: int):
        return db.get(ResponsePlaybookStep, step_id)

    def get_playbook_steps(
        self,
        db: Session,
        playbook_id: int,
        active_only: bool = True,
    ):
        query = select(ResponsePlaybookStep).where(
            ResponsePlaybookStep.playbook_id == playbook_id
        )

        if active_only:
            query = query.where(ResponsePlaybookStep.is_active.is_(True))

        query = query.order_by(ResponsePlaybookStep.step_number)
        return list(db.scalars(query).all())

    def get_step_by_number(
        self,
        db: Session,
        playbook_id: int,
        step_number: int,
    ):
        query = select(ResponsePlaybookStep).where(
            ResponsePlaybookStep.playbook_id == playbook_id,
            ResponsePlaybookStep.step_number == step_number,
        )
        return db.scalar(query)

    def create_execution(
        self,
        db: Session,
        execution: PlaybookExecution,
    ):
        db.add(execution)
        db.flush()
        return execution

    def get_execution(self, db: Session, execution_id: int):
        return db.get(PlaybookExecution, execution_id)

    def list_executions(
        self,
        db: Session,
        playbook_id: int | None = None,
        incident_id: int | None = None,
        investigation_id: int | None = None,
        skip: int = 0,
        limit: int = 100,
    ):
        query = select(PlaybookExecution)

        if playbook_id is not None:
            query = query.where(
                PlaybookExecution.playbook_id == playbook_id
            )

        if incident_id is not None:
            query = query.where(
                PlaybookExecution.incident_id == incident_id
            )

        if investigation_id is not None:
            query = query.where(
                PlaybookExecution.investigation_id == investigation_id
            )

        query = (
            query.order_by(PlaybookExecution.id.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(db.scalars(query).all())

    def create_execution_step(
        self,
        db: Session,
        step: PlaybookExecutionStep,
    ):
        db.add(step)
        db.flush()
        return step

    def get_execution_step(
        self,
        db: Session,
        step_id: int,
    ):
        return db.get(PlaybookExecutionStep, step_id)

    def get_execution_steps(
        self,
        db: Session,
        execution_id: int,
    ):
        query = (
            select(PlaybookExecutionStep)
            .where(
                PlaybookExecutionStep.execution_id == execution_id
            )
            .order_by(PlaybookExecutionStep.step_number)
        )
        return list(db.scalars(query).all())

    def create_history(
        self,
        db: Session,
        history: ResponseHistory,
    ):
        db.add(history)
        db.flush()
        return history

    def get_execution_history(
        self,
        db: Session,
        execution_id: int,
    ):
        query = (
            select(ResponseHistory)
            .where(ResponseHistory.execution_id == execution_id)
            .order_by(ResponseHistory.created_at, ResponseHistory.id)
        )
        return list(db.scalars(query).all())

    def commit(self, db: Session):
        db.commit()

    def rollback(self, db: Session):
        db.rollback()


response_playbook_repository = ResponsePlaybookRepository()
