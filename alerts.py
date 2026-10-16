
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from models.user import User
from schemas.alert import (
    AlertCategory,
    AlertCreate,
    AlertResponse,
    AlertSeverity,
    AlertStatus,
    AlertUpdate,
)
from services.alert_service import AlertService


router = APIRouter(prefix="/api/v1/alerts", tags=["Security Alerts"])

ALERT_CREATORS = ("SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST")
ALERT_UPDATERS = (
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
)


@router.post("", response_model=AlertResponse, status_code=201)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*ALERT_CREATORS)),
):
    return AlertService(db).create(payload, current_user)


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    search: str | None = Query(default=None, max_length=200),
    severity: AlertSeverity | None = None,
    status: AlertStatus | None = None,
    category: AlertCategory | None = None,
    source: str | None = Query(default=None, max_length=100),
    organization_id: int | None = Query(default=None, gt=0),
    asset_id: int | None = Query(default=None, gt=0),
    assigned_to: int | None = Query(default=None, gt=0),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return AlertService(db).list(
        search=search,
        severity=severity.value if severity else None,
        status=status.value if status else None,
        category=category.value if category else None,
        source=source,
        organization_id=organization_id,
        asset_id=asset_id,
        assigned_to=assigned_to,
        page=page,
        page_size=page_size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return AlertService(db).get(alert_id)


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*ALERT_UPDATERS)),
):
    return AlertService(db).update(alert_id, payload)
