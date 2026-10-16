
from typing import Literal

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from schemas.asset import AssetCreate, AssetResponse, AssetUpdate
from services.asset_service import AssetService

router = APIRouter(
    prefix="/api/v1/assets",
    tags=["Assets"],
)

AssetTypeFilter = Literal[
    "SERVER",
    "ENDPOINT",
    "NETWORK_DEVICE",
    "CLOUD_RESOURCE",
    "APPLICATION",
    "DATABASE",
    "OTHER",
]
CriticalityFilter = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
StatusFilter = Literal["ACTIVE", "INACTIVE", "UNDER_MAINTENANCE", "RETIRED"]


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_asset(
    data: AssetCreate,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_roles("SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST")
    ),
):
    return AssetService(db).create(data)


@router.get("", response_model=list[AssetResponse])
def list_assets(
    organization_id: int | None = Query(default=None, gt=0),
    asset_type: AssetTypeFilter | None = None,
    criticality: CriticalityFilter | None = None,
    status: StatusFilter | None = None,
    search: str | None = Query(default=None, max_length=255),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return AssetService(db).list(
        organization_id=organization_id,
        asset_type=asset_type,
        criticality=criticality,
        status=status,
        search=search,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return AssetService(db).get(asset_id)



@router.patch("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    data: AssetUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_roles("SUPER_ADMIN", "SECURITY_MANAGER")
    ),
):
    return AssetService(db).update(asset_id, data)
