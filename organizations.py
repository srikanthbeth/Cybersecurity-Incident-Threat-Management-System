
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from schemas.organization import (
    OrganizationCreate,
    OrganizationResponse,
    OrganizationUpdate,
)
from services.organization_service import OrganizationService

router = APIRouter(
    prefix="/api/v1/organizations",
    tags=["Organizations"],
)


@router.post(
    "",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_organization(
    data: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles("SUPER_ADMIN", "SECURITY_MANAGER")),
):
    return OrganizationService(db).create(data, current_user)


@router.get("", response_model=list[OrganizationResponse])
def list_organizations(
    search: str | None = Query(default=None, max_length=150),
    active_only: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return OrganizationService(db).list(search, active_only)


@router.get("/{organization_id}", response_model=OrganizationResponse)
def get_organization(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return OrganizationService(db).get(organization_id)


@router.patch(
    "/{organization_id}",
    response_model=OrganizationResponse,
)
def update_organization(
    organization_id: int,
    data: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_roles("SUPER_ADMIN", "SECURITY_MANAGER")),
):
    return OrganizationService(db).update(organization_id, data)
