
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from models.user import User
from schemas.incident import (
    ClosureRequest,
    IncidentCreate,
    IncidentHistoryResponse,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentUpdate,
)
from services.incident_service import IncidentService

incidents_router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["Incident Management"],
)


@incidents_router.post(
    "",
    response_model=IncidentResponse,
    status_code=201,
)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST")
    ),
):
    return IncidentService(db).create(payload, current_user)


@incidents_router.get("")
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, total = IncidentService(db).list(
        status=status,
        severity=severity,
        search=search,
        skip=skip,
        limit=limit,
    )
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@incidents_router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return IncidentService(db).get(incident_id)


@incidents_router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "SUPER_ADMIN",
            "SECURITY_MANAGER",
            "SECURITY_ANALYST",
            "INCIDENT_RESPONDER",
        )
    ),
):
    return IncidentService(db).update(incident_id, payload, current_user)


@incidents_router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteResponse,
    status_code=201,
)
def add_investigation_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "SUPER_ADMIN",
            "SECURITY_MANAGER",
            "SECURITY_ANALYST",
            "INCIDENT_RESPONDER",
        )
    ),
):
    return IncidentService(db).add_note(
        incident_id,
        payload.note,
        current_user,
    )


@incidents_router.get(
    "/{incident_id}/notes",
    response_model=list[IncidentNoteResponse],
)
def get_investigation_notes(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return IncidentService(db).get_notes(incident_id)


@incidents_router.get(
    "/{incident_id}/history",
    response_model=list[IncidentHistoryResponse],
)
def get_incident_history(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return IncidentService(db).get_history(incident_id)


@incidents_router.post(
    "/{incident_id}/request-closure",
    response_model=IncidentResponse,
)
def request_incident_closure(
    incident_id: int,
    payload: ClosureRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "SUPER_ADMIN",
            "SECURITY_MANAGER",
            "SECURITY_ANALYST",
            "INCIDENT_RESPONDER",
        )
    ),
):
    return IncidentService(db).request_closure(
        incident_id,
        payload.details,
        current_user,
    )


@incidents_router.post(
    "/{incident_id}/approve-closure",
    response_model=IncidentResponse,
)
def approve_incident_closure(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "SECURITY_MANAGER")
    ),
):
    return IncidentService(db).approve_closure(incident_id, current_user)
