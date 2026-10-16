from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from database import get_db
from core.dependencies import get_current_user
from schemas.vulnerability import (
    VulnerabilityAssetCreate,
    VulnerabilityAssetResponse,
    VulnerabilityCreate,
    VulnerabilityHistoryResponse,
    VulnerabilityResponse,
    VulnerabilityStatusUpdate,
    VulnerabilityUpdate,
)
from services.vulnerability_service import VulnerabilityService


router = APIRouter(
    prefix="/api/v1/vulnerabilities",
    tags=["Vulnerability Tracking"],
)

READ_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
    "VIEWER",
}

WRITE_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
}


def authorize(user, allowed_roles):
    role = getattr(user, "role", None)
    role_value = getattr(role, "value", role)

    if str(role_value).upper() not in allowed_roles:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to perform this action",
        )


def get_service(db: Session) -> VulnerabilityService:
    return VulnerabilityService(db)


@router.post(
    "",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_vulnerability(
    payload: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, WRITE_ROLES)
    return get_service(db).create(payload, current_user.id)


@router.get("", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    organization_id: int | None = Query(default=None, gt=0),
    severity: str | None = Query(
        default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"
    ),
    status_filter: str | None = Query(
        default=None,
        alias="status",
        pattern="^(OPEN|UNDER_REVIEW|IN_REMEDIATION|MITIGATED|ACCEPTED_RISK|CLOSED)$",
    ),
    search: str | None = Query(default=None, max_length=200),
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, READ_ROLES)
    return get_service(db).list(
        organization_id=organization_id,
        severity=severity,
        status=status_filter,
        search=search,
        limit=limit,
        offset=offset,
    )


@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, READ_ROLES)
    return get_service(db).get(vulnerability_id)


@router.patch("/{vulnerability_id}", response_model=VulnerabilityResponse)
def update_vulnerability(
    vulnerability_id: int,
    payload: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, WRITE_ROLES)
    return get_service(db).update(
        vulnerability_id, payload, current_user.id
    )


@router.patch(
    "/{vulnerability_id}/status",
    response_model=VulnerabilityResponse,
)
def update_vulnerability_status(
    vulnerability_id: int,
    payload: VulnerabilityStatusUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, WRITE_ROLES)
    return get_service(db).update_status(
        vulnerability_id,
        payload.status,
        current_user.id,
        payload.details,
    )


@router.post(
    "/{vulnerability_id}/assets",
    response_model=VulnerabilityAssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def link_asset(
    vulnerability_id: int,
    payload: VulnerabilityAssetCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, WRITE_ROLES)
    return get_service(db).add_asset(
        vulnerability_id, payload.asset_id, current_user.id
    )


@router.get(
    "/{vulnerability_id}/assets",
    response_model=list[VulnerabilityAssetResponse],
)
def list_affected_assets(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, READ_ROLES)
    return get_service(db).list_assets(vulnerability_id)


@router.get(
    "/{vulnerability_id}/history",
    response_model=list[VulnerabilityHistoryResponse],
)
def get_vulnerability_history(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    authorize(current_user, READ_ROLES)
    return get_service(db).history(vulnerability_id)