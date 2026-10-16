
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from database import get_db
from models.user import User
from schemas.response_playbook import (
    ExecutionCreate,
    ExecutionRead,
    ExecutionStepAssign,
    ExecutionStepRead,
    ExecutionStepUpdate,
    PlaybookCreate,
    PlaybookRead,
    PlaybookStepCreate,
    PlaybookStepRead,
    PlaybookUpdate,
    ResponseHistoryRead,
    StepApproval,
)
from services.response_playbook_service import response_playbook_service


router = APIRouter(
    prefix="/api/v1/response-playbooks",
    tags=["Response Playbooks"],
)

MANAGERS = {"SUPER_ADMIN", "SECURITY_MANAGER"}
PLAYBOOK_EDITORS = MANAGERS | {"SECURITY_ANALYST"}
RESPONDERS = PLAYBOOK_EDITORS | {"INCIDENT_RESPONDER"}


def role_name(user: User) -> str:
    value = getattr(user.role, "value", user.role)
    return str(value).upper()


def require_roles(user: User, allowed: set[str]):
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive users cannot access this resource",
        )
    if role_name(user) not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action",
        )


@router.post(
    "",
    response_model=PlaybookRead,
    status_code=status.HTTP_201_CREATED,
)
def create_playbook(
    payload: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, PLAYBOOK_EDITORS)
    return response_playbook_service.create_playbook(
        db, current_user.id, payload
    )


@router.get("", response_model=list[PlaybookRead])
def list_playbooks(
    active_only: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS | {"VIEWER"})
    return response_playbook_service.list_playbooks(db, active_only)


@router.get("/{playbook_id}", response_model=PlaybookRead)
def get_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS | {"VIEWER"})
    return response_playbook_service.get_playbook(db, playbook_id)


@router.get(
    "/{playbook_id}/steps",
    response_model=list[PlaybookStepRead],
)
def list_playbook_steps(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS | {"VIEWER"})
    return response_playbook_service.get_playbook_steps(db, playbook_id)


@router.patch("/{playbook_id}", response_model=PlaybookRead)
def update_playbook(
    playbook_id: int,
    payload: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, PLAYBOOK_EDITORS)
    return response_playbook_service.update_playbook(
        db, playbook_id, payload
    )


@router.post(
    "/{playbook_id}/steps",
    response_model=PlaybookStepRead,
    status_code=status.HTTP_201_CREATED,
)
def add_playbook_step(
    playbook_id: int,
    payload: PlaybookStepCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, PLAYBOOK_EDITORS)
    return response_playbook_service.add_step(db, playbook_id, payload)


@router.post(
    "/{playbook_id}/executions",
    response_model=ExecutionRead,
    status_code=status.HTTP_201_CREATED,
)
def start_execution(
    playbook_id: int,
    payload: ExecutionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS)
    return response_playbook_service.start_execution(
        db, current_user.id, playbook_id, payload
    )


@router.get(
    "/executions/{execution_id}",
    response_model=ExecutionRead,
)
def get_execution(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS | {"VIEWER"})
    return response_playbook_service.get_execution(db, execution_id)


@router.get(
    "/executions/{execution_id}/steps",
    response_model=list[ExecutionStepRead],
)
def list_execution_steps(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS | {"VIEWER"})
    return response_playbook_service.list_execution_steps(
        db, execution_id
    )


@router.patch(
    "/executions/{execution_id}/steps/{step_id}/assign",
    response_model=ExecutionStepRead,
)
def assign_execution_step(
    execution_id: int,
    step_id: int,
    payload: ExecutionStepAssign,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS)
    return response_playbook_service.assign_step(
        db, current_user.id, execution_id, step_id, payload
    )


@router.post(
    "/executions/{execution_id}/steps/{step_id}/approval",
    response_model=ExecutionStepRead,
)
def approve_execution_step(
    execution_id: int,
    step_id: int,
    payload: StepApproval,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, MANAGERS)
    return response_playbook_service.approve_step(
        db, current_user.id, execution_id, step_id, payload
    )


@router.patch(
    "/executions/{execution_id}/steps/{step_id}",
    response_model=ExecutionStepRead,
)
def update_execution_step(
    execution_id: int,
    step_id: int,
    payload: ExecutionStepUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS)
    return response_playbook_service.update_execution_step(
        db, current_user.id, execution_id, step_id, payload
    )


@router.get(
    "/executions/{execution_id}/history",
    response_model=list[ResponseHistoryRead],
)
def list_execution_history(
    execution_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_roles(current_user, RESPONDERS | {"VIEWER"})
    return response_playbook_service.list_history(db, execution_id)
