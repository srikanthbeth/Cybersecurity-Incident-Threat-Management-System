
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from core.dependencies import get_current_user
from schemas.correlation import (
    AlertCorrelationResponse,
    CorrelationGroupCreate,
    CorrelationGroupResponse,
    CorrelationHistoryResponse,
    CorrelationMemberCreate,
    CorrelationMemberResponse,
    DuplicateIncidentMatch,
    IncidentRelationshipCreate,
    IncidentRelationshipResponse,
)
from services.correlation_service import CorrelationService


router = APIRouter(
    prefix="/api/v1/correlation",
    tags=["Incident Correlation"],
)

CORRELATION_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
}


def authorize(user):
    role = getattr(user, "role", None)
    role_value = getattr(role, "value", role)

    if str(role_value).upper() not in CORRELATION_ROLES:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to manage incident correlation",
        )


@router.post("/groups", response_model=CorrelationGroupResponse, status_code=201)
def create_correlation_group(
    data: CorrelationGroupCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).create_group(data, current_user)


@router.get("/groups", response_model=list[CorrelationGroupResponse])
def list_correlation_groups(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).list_groups(limit, offset)


@router.post(
    "/groups/{group_id}/alerts",
    response_model=CorrelationMemberResponse,
    status_code=201,
)
def add_alert_to_correlation_group(
    group_id: int,
    data: CorrelationMemberCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).add_alert_to_group(
        group_id,
        data.alert_id,
        current_user,
    )


@router.get(
    "/groups/{group_id}/alerts",
    response_model=list[CorrelationMemberResponse],
)
def list_correlation_group_alerts(
    group_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).list_group_alerts(group_id)


@router.get(
    "/alerts/{alert_id}/related",
    response_model=AlertCorrelationResponse,
)
def correlate_alert(
    alert_id: int,
    window_minutes: int = Query(default=60, ge=1, le=10080),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).correlate_alert(
        alert_id,
        window_minutes,
    )


@router.post(
    "/incidents/{incident_id}/alerts/{alert_id}",
    response_model=CorrelationMemberResponse,
    status_code=201,
)
def link_alert_to_incident(
    incident_id: int,
    alert_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).link_alert_to_incident(
        incident_id,
        alert_id,
        current_user,
    )


@router.get(
    "/incidents/{incident_id}/duplicates",
    response_model=list[DuplicateIncidentMatch],
)
def find_duplicate_incidents(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).find_duplicate_incidents(
        incident_id,
        current_user,
    )


@router.post(
    "/incidents/{incident_id}/related",
    response_model=IncidentRelationshipResponse,
    status_code=201,
)
def relate_incidents(
    incident_id: int,
    data: IncidentRelationshipCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).relate_incidents(
        incident_id,
        data,
        current_user,
    )


@router.get(
    "/incidents/{incident_id}/related",
    response_model=list[IncidentRelationshipResponse],
)
def list_related_incidents(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).list_related_incidents(incident_id)


@router.get("/history", response_model=list[CorrelationHistoryResponse])
def list_correlation_history(
    entity_type: str | None = None,
    entity_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user)
    return CorrelationService(db).list_history(
        entity_type=entity_type,
        entity_id=entity_id,
        limit=limit,
        offset=offset,
    )
