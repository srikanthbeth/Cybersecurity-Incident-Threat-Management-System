
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.asset import Asset
from models.organization import Organization
from models.user import User
from repositories.asset_repository import AssetRepository


class AssetService:
    def __init__(self, db: Session):
        self.db = db
        self.repository = AssetRepository(db)

    def create(self, data):
        organization = self.db.get(Organization, data.organization_id)

        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found.")

        if not organization.is_active:
            raise HTTPException(
                status_code=400,
                detail="Cannot add assets to an inactive organization.",
            )

        if self.repository.get_by_tag(data.organization_id, data.asset_tag):
            raise HTTPException(
                status_code=409,
                detail="This asset tag already exists in the organization.",
            )

        if data.owner_user_id is not None:
            owner = self.db.get(User, data.owner_user_id)
            if not owner or not owner.is_active:
                raise HTTPException(
                    status_code=400,
                    detail="The specified asset owner does not exist or is inactive.",
                )

        asset = Asset(**data.model_dump())

        try:
            return self.repository.create(asset)
        except IntegrityError as exc:
            self.db.rollback()
            raise HTTPException(
                status_code=409,
                detail="The asset conflicts with an existing record.",
            ) from exc

    def list(
        self,
        organization_id=None,
        asset_type=None,
        criticality=None,
        status=None,
        search=None,
    ):
        return self.repository.list(
            organization_id=organization_id,
            asset_type=asset_type,
            criticality=criticality,
            status=status,
            search=search,
        )

    def get(self, asset_id: int):
        asset = self.repository.get_by_id(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found.")
        return asset

    def update(self, asset_id: int, data):
        asset = self.get(asset_id)
        changes = data.model_dump(exclude_unset=True)

        if "owner_user_id" in changes and changes["owner_user_id"] is not None:
            owner = self.db.get(User, changes["owner_user_id"])
            if not owner or not owner.is_active:
                raise HTTPException(
                    status_code=400,
                    detail="The specified asset owner does not exist or is inactive.",
                )

        for field, value in changes.items():
            setattr(asset, field, value)

        try:
            return self.repository.save(asset)
        except IntegrityError as exc:
            self.db.rollback()
            raise HTTPException(
                status_code=400,
                detail="The asset update conflicts with an existing record.",
            ) from exc


def get_asset_service(db: Session):
    return AssetService(db)
