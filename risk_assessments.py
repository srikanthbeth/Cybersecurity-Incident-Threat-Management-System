from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from core.dependencies import get_current_user
from schemas.risk_assessment import (
    RiskAssessmentHistoryResponse,
    RiskAssessmentResponse,
    RiskDecisionUpdate,
)
from services.risk_assessment_service import RiskAssessmentService


router = APIRouter(
    prefix="/api/v1/risk-assessments",
    tags=["Risk Assessments"],
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


def current_role(user) -> str:
    role = getattr(user, "role", "")
    return str(getattr(role, "value", role)).upper()


def require_role(user, allowed_roles: set[str]):
    if current_role(user) not in allowed_roles:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to perform this action",
        )


def get_service(db: Session = Depends(get_db)):
    return RiskAssessmentService(db)


ServiceDependency = Annotated[
    RiskAssessmentService,
    Depends(get_service),
]


@router.post(
    "/assets/{asset_id}/assess",
    response_model=RiskAssessmentResponse,
    status_code=201,
)
def assess_asset(
    asset_id: int,
    service: ServiceDependency,
    user=Depends(get_current_user),
):
    require_role(user, WRITE_ROLES)
    return service.assess_asset(asset_id, user.id)


@router.get(
    "",
    response_model=list[RiskAssessmentResponse],
)
def list_assessments(
    service: ServiceDependency,
    asset_id: int | None = Query(default=None, gt=0),
    risk_level: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user=Depends(get_current_user),
):
    require_role(user, READ_ROLES)
    return service.list_assessments(
        asset_id=asset_id,
        risk_level=risk_level,
        status=status,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/assets/{asset_id}/latest",
    response_model=RiskAssessmentResponse,
)
def get_latest_assessment(
    asset_id: int,
    service: ServiceDependency,
    user=Depends(get_current_user),
):
    require_role(user, READ_ROLES)
    return service.get_latest_for_asset(asset_id)


@router.get(
    "/{assessment_id}",
    response_model=RiskAssessmentResponse,
)
def get_assessment(
    assessment_id: int,
    service: ServiceDependency,
    user=Depends(get_current_user),
):
    require_role(user, READ_ROLES)
    return service.get_assessment(assessment_id)


@router.patch(
    "/{assessment_id}/decision",
    response_model=RiskAssessmentResponse,
)
def update_decision(
    assessment_id: int,
    payload: RiskDecisionUpdate,
    service: ServiceDependency,
    user=Depends(get_current_user),
):
    require_role(user, WRITE_ROLES)
    return service.update_decision(
        assessment_id,
        payload,
        user.id,
    )


@router.get(
    "/{assessment_id}/history",
    response_model=list[RiskAssessmentHistoryResponse],
)
def get_assessment_history(
    assessment_id: int,
    service: ServiceDependency,
    user=Depends(get_current_user),
):
    require_role(user, READ_ROLES)
    return service.get_history(assessment_id)