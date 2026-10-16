
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.security_team import SecurityTeam, SecurityTeamMember
from models.user import User
from repositories.security_team_repository import SecurityTeamRepository
from schemas.security_team import SecurityTeamCreate, SecurityTeamUpdate


class SecurityTeamService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = SecurityTeamRepository(db)

    def create_team(self, payload: SecurityTeamCreate, actor: User):
        code = payload.code.strip().upper()

        if self.repo.get_by_code(code):
            raise HTTPException(
                status_code=409,
                detail="A security team with this code already exists.",
            )

        team = SecurityTeam(
            name=payload.name.strip(),
            code=code,
            description=payload.description,
            created_by=actor.id,
        )
        self.db.add(team)

        try:
            self.db.commit()
            self.db.refresh(team)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=409,
                detail="A security team with this code already exists.",
            )

        return team

    def list_teams(self, search: str | None = None, active_only: bool = False):
        return self.repo.list_teams(search, active_only)

    def get_team(self, team_id: int):
        team = self.repo.get_team(team_id)
        if team is None:
            raise HTTPException(status_code=404, detail="Security team not found.")
        return team

    def update_team(self, team_id: int, payload: SecurityTeamUpdate):
        team = self.get_team(team_id)

        for field, value in payload.model_dump(exclude_unset=True).items():
            if field == "name" and value is not None:
                value = value.strip()
                if len(value) < 2:
                    raise HTTPException(
                        status_code=422,
                        detail="Team name must contain at least 2 characters.",
                    )
            setattr(team, field, value)

        self.db.commit()
        self.db.refresh(team)
        return team

    def assign_analyst(self, team_id: int, user_id: int, actor: User):
        team = self.get_team(team_id)

        if not team.is_active:
            raise HTTPException(
                status_code=400,
                detail="Cannot assign an analyst to an inactive team.",
            )

        user = self.db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")

        if not user.is_active:
            raise HTTPException(
                status_code=400,
                detail="Cannot assign an inactive user.",
            )

        if user.role != "SECURITY_ANALYST":
            raise HTTPException(
                status_code=422,
                detail="Only active security analysts can be assigned.",
            )

        if self.repo.get_membership(team_id, user_id):
            raise HTTPException(
                status_code=409,
                detail="This analyst is already assigned to the team.",
            )

        membership = SecurityTeamMember(
            team_id=team_id,
            user_id=user_id,
            assigned_by=actor.id,
        )
        self.db.add(membership)

        try:
            self.db.commit()
            self.db.refresh(membership)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=409,
                detail="This analyst is already assigned to the team.",
            )

        return membership

    def remove_member(self, team_id: int, user_id: int):
        self.get_team(team_id)
        membership = self.repo.get_membership(team_id, user_id)

        if membership is None:
            raise HTTPException(
                status_code=404,
                detail="Team membership not found.",
            )

        self.db.delete(membership)
        self.db.commit()
        return {"message": "Analyst removed from security team."}

    def list_members(self, team_id: int):
        self.get_team(team_id)
        return self.repo.list_members(team_id)
