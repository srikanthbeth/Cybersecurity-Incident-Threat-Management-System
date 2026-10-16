
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from models.user import User
from schemas.remediation import (
    RemediationCancel,
    RemediationEvidenceCreate,
    RemediationEvidenceResponse,
    RemediationHistoryResponse,
    RemediationReview,
    RemediationStart,
    RemediationSubmit,
    RemediationTaskCreate,
    RemediationTaskResponse,
    RemediationTaskUpdate,
)
from services.remediation_service import RemediationService


router = APIRouter(
    prefix="/api/v1/remediations",
    tags=["Remediation Workflow"],
)

READ_ROLES = (
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
    "VIEWER",
)

WRITE_ROLES = (
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
)

REVIEW_ROLES = ("SUPER_ADMIN", "SECURITY_MANAGER")


@router.post(
    "",
    response_model=RemediationTaskResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_remediation(
    payload: RemediationTaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITE_ROLES)),
):
    return RemediationService(db).create(payload, current_user)


@router.get("", response_model=list[RemediationTaskResponse])
def list_remediations(
    status_filter: str | None = Query(
        default=None,
        alias="status",
        pattern="^(OPEN|IN_PROGRESS|PENDING_APPROVAL|REJECTED|COMPLETED|CANCELLED)$",
    ),
    priority: str | None = Query(
        default=None,
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
    ),
    assigned_team_id: int | None = Query(default=None, gt=0),
    assigned_to: int | None = Query(default=None, gt=0),
    overdue_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return RemediationService(db).list(
        status=status_filter,
        priority=priority,
        assigned_team_id=assigned_team_id,
        assigned_to=assigned_to,
        overdue_only=overdue_only,
        limit=limit,
        offset=offset,
    )


@router.get("/overdue", response_model=list[RemediationTaskResponse])
def list_overdue_remediations(
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return RemediationService(db).list(
        overdue_only=True,
        limit=limit,
        offset=offset,
    )


@router.get("/{task_id}", response_model=RemediationTaskResponse)
def get_remediation(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return RemediationService(db).get(task_id)


@router.patch("/{task_id}", response_model=RemediationTaskResponse)
def update_remediation(
    task_id: int,
    payload: RemediationTaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITE_ROLES)),
):
    return RemediationService(db).update(task_id, payload, current_user)


@router.post("/{task_id}/start", response_model=RemediationTaskResponse)
def start_remediation(
    task_id: int,
    payload: RemediationStart,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITE_ROLES)),
):
    return RemediationService(db).start(
        task_id, payload.details, current_user
    )


@router.post(
    "/{task_id}/evidence",
    response_model=RemediationEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_remediation_evidence(
    task_id: int,
    payload: RemediationEvidenceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITE_ROLES)),
):
    return RemediationService(db).add_evidence(
        task_id, payload, current_user
    )


@router.get(
    "/{task_id}/evidence",
    response_model=list[RemediationEvidenceResponse],
)
def list_remediation_evidence(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return RemediationService(db).list_evidence(task_id)


@router.post(
    "/{task_id}/submit",
    response_model=RemediationTaskResponse,
)
def submit_remediation(
    task_id: int,
    payload: RemediationSubmit,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITE_ROLES)),
):
    return RemediationService(db).submit(
        task_id, payload.details, current_user
    )


@router.post(
    "/{task_id}/review",
    response_model=RemediationTaskResponse,
)
def review_remediation(
    task_id: int,
    payload: RemediationReview,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*REVIEW_ROLES)),
):
    return RemediationService(db).review(
        task_id, payload, current_user
    )


@router.post(
    "/{task_id}/cancel",
    response_model=RemediationTaskResponse,
)
def cancel_remediation(
    task_id: int,
    payload: RemediationCancel,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITE_ROLES)),
):
    return RemediationService(db).cancel(
        task_id, payload.reason, current_user
    )


@router.get(
    "/{task_id}/history",
    response_model=list[RemediationHistoryResponse],
)
def get_remediation_history(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return RemediationService(db).history(task_id)
