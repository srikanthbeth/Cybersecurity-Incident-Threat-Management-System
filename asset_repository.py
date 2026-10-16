
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.asset import Asset


class AssetRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, asset_id: int):
        return self.db.get(Asset, asset_id)

    def get_by_tag(self, organization_id: int, asset_tag: str):
        statement = select(Asset).where(
            Asset.organization_id == organization_id,
            Asset.asset_tag == asset_tag.upper(),
        )
        return self.db.scalar(statement)

    def list(
        self,
        organization_id: int | None = None,
        asset_type: str | None = None,
        criticality: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ):
        statement = select(Asset).order_by(Asset.id.desc())

        if organization_id is not None:
            statement = statement.where(
                Asset.organization_id == organization_id
            )

        if asset_type:
            statement = statement.where(Asset.asset_type == asset_type)

        if criticality:
            statement = statement.where(Asset.criticality == criticality)

        if status:
            statement = statement.where(Asset.status == status)

        if search:
            statement = statement.where(
                Asset.name.ilike(f"%{search}%")
                | Asset.asset_tag.ilike(f"%{search}%")
                | Asset.hostname.ilike(f"%{search}%")
                | Asset.ip_address.ilike(f"%{search}%")
            )

        return list(self.db.scalars(statement).all())

    def create(self, asset: Asset):
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def save(self, asset: Asset):
        self.db.commit()
        self.db.refresh(asset)
        return asset
