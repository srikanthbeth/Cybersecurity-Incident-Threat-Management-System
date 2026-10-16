
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.alert import Alert
from models.asset import Asset
from models.organization import Organization
from models.user import User
from repositories.alert_repository import AlertRepository
from schemas.alert import AlertCreate, AlertUpdate


ASSIGNABLE_ROLES = {"SECURITY_ANALYST", "INCIDENT_RESPONDER"}

ALLOWED_TRANSITIONS = {
    "NEW": {"ACKNOWLEDGED", "INVESTIGATING", "FALSE_POSITIVE"},
    "ACKNOWLEDGED": {"INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"},
    "RESOLVED": {"INVESTIGATING"},
    "FALSE_POSITIVE": {"INVESTIGATING"},
}


class AlertService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = AlertRepository(db)

    def _validate_assignee(self, user_id: int | None):
        if user_id is None:
            return

        user = self.db.get(User, user_id)

        if user is None:
            raise HTTPException(
                status_code=404,
                detail="Assigned user not found.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=400,
                detail="Cannot assign an alert to an inactive user.",
            )

        if user.role not in ASSIGNABLE_ROLES:
            raise HTTPException(
                status_code=422,
                detail="Alerts can only be assigned to active analysts or incident responders.",
            )

    def _validate_asset_and_organization(
        self,
        asset_id: int | None,
        organization_id: int | None,
    ):
        asset = None

        if organization_id is not None:
            organization = self.db.get(Organization, organization_id)

            if organization is None:
                raise HTTPException(
                    status_code=404,
                    detail="Organization not found.",
                )

            if not organization.is_active:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot create an alert for an inactive organization.",
                )

        if asset_id is not None:
            asset = self.db.get(Asset, asset_id)

            if asset is None:
                raise HTTPException(
                    status_code=404,
                    detail="Asset not found.",
                )

            if (
                organization_id is not None
                and asset.organization_id != organization_id
            ):
                raise HTTPException(
                    status_code=422,
                    detail="Asset does not belong to the specified organization.",
                )

            if organization_id is None:
                organization = self.db.get(
                    Organization,
                    asset.organization_id,
                )

                if organization is None or not organization.is_active:
                    raise HTTPException(
                        status_code=400,
                        detail="The asset's organization is missing or inactive.",
                    )

        return asset

    def create(self, payload: AlertCreate, actor: User):
        data = payload.model_dump()

        source = data["source"].strip()
        external_id = data["external_alert_id"]

        if external_id is not None:
            external_id = external_id.strip()

            existing = self.repo.get_by_external_id(
                source,
                external_id,
            )

            if existing is not None:
                raise HTTPException(
                    status_code=409,
                    detail="An alert with this source and external ID already exists.",
                )

        asset = self._validate_asset_and_organization(
            data["asset_id"],
            data["organization_id"],
        )

        if asset is not None and data["organization_id"] is None:
            data["organization_id"] = asset.organization_id

        self._validate_assignee(data["assigned_to"])

        data["source"] = source
        data["external_alert_id"] = external_id
        data["detected_at"] = (
            data["detected_at"] or datetime.now(timezone.utc)
        )
        data["created_by"] = actor.id
        data["status"] = "NEW"

        alert = Alert(**data)
        self.db.add(alert)

        try:
            self.db.commit()
            self.db.refresh(alert)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=409,
                detail="A duplicate alert was detected.",
            )

        return alert

    def list(self, **filters):
        return self.repo.list_alerts(**filters)

    def get(self, alert_id: int):
        alert = self.repo.get_by_id(alert_id)

        if alert is None:
            raise HTTPException(
                status_code=404,
                detail="Alert not found.",
            )

        return alert

    def update(self, alert_id: int, payload: AlertUpdate):
        alert = self.get(alert_id)
        data = payload.model_dump(exclude_unset=True)

        if "assigned_to" in data:
            self._validate_assignee(data["assigned_to"])

        if data.get("status") is not None:
            new_status = data["status"]

            if new_status != alert.status:
                allowed = ALLOWED_TRANSITIONS.get(alert.status, set())

                if new_status not in allowed:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"Cannot change alert status from "
                            f"{alert.status} to {new_status}."
                        ),
                    )

            if new_status == "RESOLVED":
                alert.resolved_at = datetime.now(timezone.utc)
            elif new_status in {"INVESTIGATING", "ACKNOWLEDGED"}:
                alert.resolved_at = None

        for field, value in data.items():
            if value is not None or field in {"description", "assigned_to"}:
                setattr(alert, field, value)

        try:
            self.db.commit()
            self.db.refresh(alert)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(
                status_code=400,
                detail="The alert update violates a data constraint.",
            )

        return alert
