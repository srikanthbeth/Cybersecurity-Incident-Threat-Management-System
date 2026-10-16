
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from models.alert import Alert


class AlertRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, alert_id: int):
        return self.db.get(Alert, alert_id)

    def get_by_external_id(self, source: str, external_id: str):
        return self.db.scalar(
            select(Alert).where(
                Alert.source == source,
                Alert.external_alert_id == external_id,
            )
        )

    def list_alerts(
        self,
        search: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        source: str | None = None,
        organization_id: int | None = None,
        asset_id: int | None = None,
        assigned_to: int | None = None,
        page: int = 1,
        page_size: int = 20,
    ):
        query = select(Alert)

        if search:
            term = f"%{search.strip()}%"
            query = query.where(
                or_(
                    Alert.title.ilike(term),
                    Alert.description.ilike(term),
                    Alert.external_alert_id.ilike(term),
                )
            )

        if severity:
            query = query.where(Alert.severity == severity)
        if status:
            query = query.where(Alert.status == status)
        if category:
            query = query.where(Alert.category == category)
        if source:
            query = query.where(Alert.source.ilike(f"%{source.strip()}%"))
        if organization_id is not None:
            query = query.where(Alert.organization_id == organization_id)
        if asset_id is not None:
            query = query.where(Alert.asset_id == asset_id)
        if assigned_to is not None:
            query = query.where(Alert.assigned_to == assigned_to)

        query = query.order_by(Alert.detected_at.desc(), Alert.id.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        return list(self.db.scalars(query).all())
