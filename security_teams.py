
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from models.user import User
from schemas.security_team import (
    AnalystAssignmentRequest,
    SecurityTeamCreate,
    SecurityTeamMemberResponse,
    SecurityTeamResponse,
    SecurityTeamUpdate,
)
from services.security_team_service import SecurityTeamService


router = APIRouter(
    prefix="/api/v1/security-teams",
    tags=["Security Teams"],
)

TEAM_MANAGERS = ("SUPER_ADMIN", "SECURITY_MANAGER")


@router.post("", response_model=SecurityTeamResponse, status_code=201)
def create_security_team(
    payload: SecurityTeamCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*TEAM_MANAGERS)),
):
    return SecurityTeamService(db).create_team(payload, current_user)


@router.get("", response_model=list[SecurityTeamResponse])
def list_security_teams(
    search: str | None = Query(default=None, max_length=120),
    active_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return SecurityTeamService(db).list_teams(search, active_only)


@router.get("/{team_id}", response_model=SecurityTeamResponse)
def get_security_team(
    team_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return SecurityTeamService(db).get_team(team_id)


@router.patch("/{team_id}", response_model=SecurityTeamResponse)
def update_security_team(
    team_id: int,
    payload: SecurityTeamUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*TEAM_MANAGERS)),
):
    return SecurityTeamService(db).update_team(team_id, payload)


@router.post(
    "/{team_id}/analysts",
    response_model=SecurityTeamMemberResponse,
    status_code=201,
)
def assign_analyst(
    team_id: int,
    payload: AnalystAssignmentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*TEAM_MANAGERS)),
):
    return SecurityTeamService(db).assign_analyst(
        team_id=team_id,
        user_id=payload.user_id,
        actor=current_user,
    )


@router.get(
    "/{team_id}/analysts",
    response_model=list[SecurityTeamMemberResponse],
)
def list_team_analysts(
    team_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return SecurityTeamService(db).list_members(team_id)


@router.delete("/{team_id}/analysts/{user_id}", status_code=200)
def remove_analyst(
    team_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*TEAM_MANAGERS)),
):
    return SecurityTeamService(db).remove_member(team_id, user_id)
