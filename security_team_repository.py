
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.security_team import SecurityTeam, SecurityTeamMember


class SecurityTeamRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_team(self, team_id: int):
        return self.db.get(SecurityTeam, team_id)

    def get_by_code(self, code: str):
        return self.db.scalar(
            select(SecurityTeam).where(SecurityTeam.code == code.upper())
        )

    def list_teams(self, search: str | None = None, active_only: bool = False):
        query = select(SecurityTeam)

        if search:
            term = f"%{search.strip()}%"
            query = query.where(
                SecurityTeam.name.ilike(term)
                | SecurityTeam.code.ilike(term)
            )

        if active_only:
            query = query.where(SecurityTeam.is_active.is_(True))

        return list(
            self.db.scalars(query.order_by(SecurityTeam.id.desc())).all()
        )

    def get_membership(self, team_id: int, user_id: int):
        return self.db.scalar(
            select(SecurityTeamMember).where(
                SecurityTeamMember.team_id == team_id,
                SecurityTeamMember.user_id == user_id,
            )
        )

    def list_members(self, team_id: int):
        return list(
            self.db.scalars(
                select(SecurityTeamMember)
                .where(SecurityTeamMember.team_id == team_id)
                .order_by(SecurityTeamMember.id)
            ).all()
        )
