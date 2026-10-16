
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from database import get_db
from repositories.audit_log_repository import AuditLogRepository
from schemas.audit_log import (
    AuditLogListResponse,
    AuditLogResponse,
    AuditLogVerifyResponse,
)
from services.audit_log_service import AuditLogService


router = APIRouter(
    prefix="/api/v1/audit-logs",
    tags=["Audit Logs"],
)


AUDIT_READ_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "AUDITOR",
}

AUDIT_VERIFY_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
}


def normalize_role(user) -> str:
    return str(user.role).upper().split(".")[-1].replace(" ", "_")


def require_audit_read_role(user):
    if normalize_role(user) not in AUDIT_READ_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit log access role required",
        )


def require_audit_verify_role(user):
    if normalize_role(user) not in AUDIT_VERIFY_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit verification management role required",
        )


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    user_id: int | None = Query(default=None, ge=1),
    action: str | None = Query(default=None, min_length=1, max_length=100),
    entity_type: str | None = Query(
        default=None, min_length=1, max_length=100
    ),
    entity_id: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_audit_read_role(current_user)

    items, total = AuditLogRepository.list_logs(
        db,
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        limit=limit,
        offset=offset,
    )

    return AuditLogListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/verify",
    response_model=AuditLogVerifyResponse,
)
def verify_audit_log_chain(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_audit_verify_role(current_user)
    return AuditLogService.verify_chain(db)


@router.get(
    "/{audit_log_id}",
    response_model=AuditLogResponse,
)
def get_audit_log(
    audit_log_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    require_audit_read_role(current_user)

    audit_log = AuditLogRepository.get_by_id(db, audit_log_id)

    if audit_log is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )

    return audit_log
