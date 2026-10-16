from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from models.user import User
from schemas.investigation import (
    EvidenceCreate,
    EvidenceResponse,
    InvestigationCreate,
    InvestigationHistoryResponse,
    InvestigationNoteCreate,
    InvestigationNoteResponse,
    InvestigationResponse,
    InvestigationUpdate,
)
from services.investigation_service import InvestigationService


router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["Investigation Management"],
)

INVESTIGATION_WRITERS = (
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
)


@router.post("", response_model=InvestigationResponse, status_code=201)
def create_investigation(
    payload: InvestigationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*INVESTIGATION_WRITERS)),
):
    return InvestigationService(db).create(payload, current_user)


@router.get("")
def list_investigations(
    status: str | None = Query(default=None, max_length=30),
    priority: str | None = Query(default=None, max_length=20),
    search: str | None = Query(default=None, max_length=200),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, total = InvestigationService(db).list(
        status=status,
        priority=priority,
        search=search,
        skip=skip,
        limit=limit,
    )
    return {"items": items, "total": total, "skip": skip, "limit": limit}


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return InvestigationService(db).get(investigation_id)


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
def update_investigation(
    investigation_id: int,
    payload: InvestigationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*INVESTIGATION_WRITERS)),
):
    return InvestigationService(db).update(
        investigation_id, payload, current_user
    )


@router.post(
    "/{investigation_id}/notes",
    response_model=InvestigationNoteResponse,
    status_code=201,
)
def add_investigation_note(
    investigation_id: int,
    payload: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*INVESTIGATION_WRITERS)),
):
    return InvestigationService(db).add_note(
        investigation_id, payload.note, current_user
    )


@router.get(
    "/{investigation_id}/notes",
    response_model=list[InvestigationNoteResponse],
)
def list_investigation_notes(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return InvestigationService(db).get_notes(investigation_id)


@router.post(
    "/{investigation_id}/evidence",
    response_model=EvidenceResponse,
    status_code=201,
)
def add_investigation_evidence(
    investigation_id: int,
    payload: EvidenceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*INVESTIGATION_WRITERS)),
):
    return InvestigationService(db).add_evidence(
        investigation_id, payload, current_user
    )


@router.get(
    "/{investigation_id}/evidence",
    response_model=list[EvidenceResponse],
)
def list_investigation_evidence(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return InvestigationService(db).get_evidence(investigation_id, current_user)


@router.get(
    "/{investigation_id}/timeline",
    response_model=list[InvestigationHistoryResponse],
)
def get_investigation_timeline(
    investigation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return InvestigationService(db).get_history(investigation_id)