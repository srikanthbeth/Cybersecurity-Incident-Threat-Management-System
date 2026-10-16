
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from database import get_db
from schemas.sla import (
    IncidentSLARead,
    SLADeadlineItem,
    SLAEventUpdate,
    SLAPolicyCreate,
    SLAPolicyRead,
    SLAPolicyUpdate,
    SLASummary,
)
from services.sla_service import SLAService


router = APIRouter(prefix="/api/v1/sla", tags=["SLA Management"])

MANAGEMENT_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
}

RESPONSE_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
}


def normalize_role(user) -> str:
    return str(user.role).upper().split(".")[-1].replace(" ", "_")


def require_management_role(user):
    if normalize_role(user) not in MANAGEMENT_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Management role required",
        )


def require_response_role(user):
    if normalize_role(user) not in RESPONSE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Incident response role required",
        )


@router.post(
    "/policies",
    response_model=SLAPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
def create_sla_policy(
    payload: SLAPolicyCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_management_role(current_user)
    return SLAService(db).create_policy(payload)


@router.get("/policies", response_model=list[SLAPolicyRead])
def list_sla_policies(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return SLAService(db).list_policies()


@router.get("/policies/{policy_id}", response_model=SLAPolicyRead)
def get_sla_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return SLAService(db).get_policy(policy_id)


@router.patch("/policies/{policy_id}", response_model=SLAPolicyRead)
def update_sla_policy(
    policy_id: int,
    payload: SLAPolicyUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_management_role(current_user)
    return SLAService(db).update_policy(policy_id, payload)


@router.post(
    "/incidents/{incident_id}",
    response_model=IncidentSLARead,
    status_code=status.HTTP_201_CREATED,
)
def start_incident_sla(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_response_role(current_user)
    return SLAService(db).ensure_incident_sla(incident_id)


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentSLARead,
)
def get_incident_sla(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return SLAService(db).get_incident_sla(incident_id)


@router.post(
    "/incidents/{incident_id}/events",
    response_model=IncidentSLARead,
)
def record_incident_sla_event(
    incident_id: int,
    payload: SLAEventUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_response_role(current_user)
    return SLAService(db).record_event(incident_id, payload)


@router.get("/breached", response_model=list[SLADeadlineItem])
def list_breached_sla_deadlines(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return SLAService(db).list_deadlines(kind="breached")


@router.get("/approaching", response_model=list[SLADeadlineItem])
def list_approaching_sla_deadlines(
    within_minutes: int = Query(default=30, ge=1, le=10080),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return SLAService(db).list_deadlines(
        kind="approaching",
        within_minutes=within_minutes,
    )


@router.get("/summary", response_model=SLASummary)
def get_sla_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return SLAService(db).get_summary()


@router.post(
    "/incidents/{incident_id}/escalate",
    response_model=IncidentSLARead,
)
def escalate_incident_sla(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_response_role(current_user)
    return SLAService(db).mark_escalated(incident_id)
