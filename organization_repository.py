
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.organization import Organization


class OrganizationRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, organization_id: int):
        return self.db.get(Organization, organization_id)

    def get_by_code(self, code: str):
        statement = select(Organization).where(
            Organization.code == code.upper()
        )
        return self.db.scalar(statement)

    def list(self, search: str | None = None, active_only: bool = False):
        statement = select(Organization).order_by(Organization.id.desc())

        if search:
            statement = statement.where(
                Organization.name.ilike(f"%{search}%")
                | Organization.code.ilike(f"%{search}%")
            )

        if active_only:
            statement = statement.where(Organization.is_active.is_(True))

        return list(self.db.scalars(statement).all())

    def create(self, organization: Organization):
        self.db.add(organization)
        self.db.commit()
        self.db.refresh(organization)
        return organization

    def save(self, organization: Organization):
        self.db.commit()
        self.db.refresh(organization)
        return organization
