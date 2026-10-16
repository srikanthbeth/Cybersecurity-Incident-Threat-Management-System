
from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.alert import Alert
from models.incident import Incident
from models.incident_alert import IncidentAlert
from models.incident_history import IncidentHistory
from models.incident_note import IncidentNote


class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, incident_id: int):
        return (
            self.db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

    def get_by_number(self, incident_number: str):
        return (
            self.db.query(Incident)
            .filter(Incident.incident_number == incident_number)
            .first()
        )

    def get_by_alert(self, alert_id: int):
        link = (
            self.db.query(IncidentAlert)
            .filter(IncidentAlert.alert_id == alert_id)
            .first()
        )
        return self.get(link.incident_id) if link else None

    def get_alert(self, alert_id: int):
        return self.db.query(Alert).filter(Alert.id == alert_id).first()

    def list(self, status=None, severity=None, search=None, skip=0, limit=20):
        query = self.db.query(Incident)

        if status:
            query = query.filter(Incident.status == status)
        if severity:
            query = query.filter(Incident.severity == severity)
        if search:
            term = f"%{search}%"
            query = query.filter(
                or_(
                    Incident.incident_number.ilike(term),
                    Incident.title.ilike(term),
                    Incident.description.ilike(term),
                )
            )

        total = query.count()
        items = (
            query.order_by(Incident.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )
        return items, total

    def add_history(
        self,
        incident_id: int,
        actor_id: int,
        action: str,
        old_value=None,
        new_value=None,
        details=None,
    ):
        entry = IncidentHistory(
            incident_id=incident_id,
            actor_id=actor_id,
            action=action,
            old_value=old_value,
            new_value=new_value,
            details=details,
        )
        self.db.add(entry)
        return entry

    def add_note(self, incident_id: int, author_id: int, note: str):
        entry = IncidentNote(
            incident_id=incident_id,
            author_id=author_id,
            note=note,
        )
        self.db.add(entry)
        return entry

    def get_notes(self, incident_id: int):
        return (
            self.db.query(IncidentNote)
            .filter(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at.asc())
            .all()
        )

    def get_history(self, incident_id: int):
        return (
            self.db.query(IncidentHistory)
            .filter(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.created_at.asc())
            .all()
        )
