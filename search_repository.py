
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from models.alert import Alert
from models.asset import Asset
from models.incident import Incident
from models.incident_alert import IncidentAlert
from models.organization import Organization


class SearchRepository:
    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _date_bounds(
        start_date: date | None,
        end_date: date | None,
    ):
        if start_date and end_date and start_date > end_date:
            raise ValueError("start_date must be on or before end_date")

        start = (
            datetime.combine(start_date, time.min, tzinfo=timezone.utc)
            if start_date
            else None
        )
        end = (
            datetime.combine(
                end_date + timedelta(days=1),
                time.min,
                tzinfo=timezone.utc,
            )
            if end_date
            else None
        )
        return start, end

    def search(
        self,
        *,
        q: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        asset_id: int | None = None,
        analyst_id: int | None = None,
        organization_name: str | None = None,
        incident_number: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> list[dict]:
        start, end = self._date_bounds(start_date, end_date)

        incidents_query = (
            self.db.query(Incident, Organization.name.label("org_name"))
            .outerjoin(
                Organization,
                Organization.id == Incident.organization_id,
            )
        )

        alerts_query = (
            self.db.query(Alert, Organization.name.label("org_name"))
            .outerjoin(
                Organization,
                Organization.id == Alert.organization_id,
            )
        )

        if severity:
            incidents_query = incidents_query.filter(
                func.lower(Incident.severity) == severity.lower()
            )
            alerts_query = alerts_query.filter(
                func.lower(Alert.severity) == severity.lower()
            )

        if status:
            incidents_query = incidents_query.filter(
                func.lower(Incident.status) == status.lower()
            )
            alerts_query = alerts_query.filter(
                func.lower(Alert.status) == status.lower()
            )

        if analyst_id is not None:
            incidents_query = incidents_query.filter(
                Incident.assigned_to == analyst_id
            )
            alerts_query = alerts_query.filter(
                Alert.assigned_to == analyst_id
            )

        if organization_name:
            pattern = f"%{organization_name.strip()}%"
            incidents_query = incidents_query.filter(
                Organization.name.ilike(pattern)
            )
            alerts_query = alerts_query.filter(
                Organization.name.ilike(pattern)
            )

        if start:
            incidents_query = incidents_query.filter(
                Incident.created_at >= start
            )
            alerts_query = alerts_query.filter(Alert.created_at >= start)

        if end:
            incidents_query = incidents_query.filter(
                Incident.created_at < end
            )
            alerts_query = alerts_query.filter(Alert.created_at < end)

        if q and q.strip():
            pattern = f"%{q.strip()}%"
            incidents_query = incidents_query.filter(
                or_(
                    Incident.title.ilike(pattern),
                    Incident.description.ilike(pattern),
                    Incident.incident_number.ilike(pattern),
                    Incident.category.ilike(pattern),
                )
            )
            alerts_query = alerts_query.filter(
                or_(
                    Alert.title.ilike(pattern),
                    Alert.description.ilike(pattern),
                    Alert.source.ilike(pattern),
                    Alert.external_alert_id.ilike(pattern),
                    Alert.category.ilike(pattern),
                )
            )

        if incident_number and incident_number.strip():
            incidents_query = incidents_query.filter(
                Incident.incident_number.ilike(
                    f"%{incident_number.strip()}%"
                )
            )
            # A reference-number filter only matches incidents.
            alerts_query = alerts_query.filter(False)

        if asset_id is not None:
            alerts_query = alerts_query.filter(Alert.asset_id == asset_id)

            incidents_query = (
                incidents_query
                .join(
                    IncidentAlert,
                    IncidentAlert.incident_id == Incident.id,
                )
                .join(
                    Alert,
                    Alert.id == IncidentAlert.alert_id,
                )
                .filter(Alert.asset_id == asset_id)
                .distinct()
            )

        incident_rows = incidents_query.all()
        alert_rows = alerts_query.all()

        results = []

        for incident, org_name in incident_rows:
            results.append({
                "record_type": "incident",
                "id": incident.id,
                "reference": incident.incident_number,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "asset_id": None,
                "analyst_id": incident.assigned_to,
                "organization_id": incident.organization_id,
                "organization_name": org_name,
                "created_at": incident.created_at,
            })

        for alert, org_name in alert_rows:
            results.append({
                "record_type": "alert",
                "id": alert.id,
                "reference": alert.external_alert_id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "status": alert.status,
                "asset_id": alert.asset_id,
                "analyst_id": alert.assigned_to,
                "organization_id": alert.organization_id,
                "organization_name": org_name,
                "created_at": alert.created_at,
            })

        return results
