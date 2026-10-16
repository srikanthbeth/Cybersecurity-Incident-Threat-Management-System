
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.organization import Organization
from repositories.organization_repository import OrganizationRepository


class OrganizationService:
    def __init__(self, db: Session):
        self.db = db
        self.repository = OrganizationRepository(db)

    def create(self, data, current_user):
        code = data.code.strip().upper()

        if self.repository.get_by_code(code):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An organization with this code already exists.",
            )

        organization = Organization(
            name=data.name.strip(),
            code=code,
            description=data.description,
            industry=data.industry,
            contact_email=(
                str(data.contact_email) if data.contact_email else None
            ),
            created_by=current_user.id,
        )

        try:
            return self.repository.create(organization)
        except IntegrityError as exc:
            self.db.rollback()
            raise HTTPException(
                status_code=409,
                detail="An organization with this code already exists.",
            ) from exc

    def list(self, search=None, active_only=False):
        return self.repository.list(search, active_only)

    def get(self, organization_id: int):
        organization = self.repository.get_by_id(organization_id)
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found.")
        return organization

    def update(self, organization_id: int, data):
        organization = self.get(organization_id)
        changes = data.model_dump(exclude_unset=True)

        for field, value in changes.items():
            if field == "name" and value is not None:
                value = value.strip()
            if field == "contact_email" and value is not None:
                value = str(value)
            setattr(organization, field, value)

        return self.repository.save(organization)


def get_organization_service(db: Session):
    return OrganizationService(db)
