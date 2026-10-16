from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.alert import Alert
from models.asset import Asset
from models.incident import Incident
from models.investigation import Investigation
from models.investigation_evidence import InvestigationEvidence
from models.investigation_history import InvestigationHistory
from models.investigation_note import InvestigationNote


class InvestigationRepository:
    def __init__(self, db: Session):
        self.db = db

    def get(self, investigation_id: int):
        return self.db.get(Investigation, investigation_id)

    def get_incident(self, incident_id: int):
        return self.db.get(Incident, incident_id)

    def get_alert(self, alert_id: int):
        return self.db.get(Alert, alert_id)

    def get_asset(self, asset_id: int):
        return self.db.get(Asset, asset_id)

    def list(self, status=None, priority=None, search=None, skip=0, limit=20):
        query = self.db.query(Investigation)

        if status:
            query = query.filter(Investigation.status == status)
        if priority:
            query = query.filter(Investigation.priority == priority)
        if search:
            term = f"%{search}%"
            query = query.filter(
                or_(
                    Investigation.investigation_number.ilike(term),
                    Investigation.title.ilike(term),
                    Investigation.description.ilike(term),
                )
            )

        total = query.count()
        items = (
            query.order_by(Investigation.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )
        return items, total

    def add_history(self, investigation_id, actor_id, action, details=None):
        item = InvestigationHistory(
            investigation_id=investigation_id,
            actor_id=actor_id,
            action=action,
            details=details,
        )
        self.db.add(item)
        return item

    def add_note(self, investigation_id, author_id, note):
        item = InvestigationNote(
            investigation_id=investigation_id,
            author_id=author_id,
            note=note,
        )
        self.db.add(item)
        return item

    def get_notes(self, investigation_id):
        return (
            self.db.query(InvestigationNote)
            .filter(InvestigationNote.investigation_id == investigation_id)
            .order_by(InvestigationNote.created_at.asc())
            .all()
        )

    def add_evidence(
        self,
        investigation_id,
        recorded_by,
        reference,
        evidence_type,
        description,
        is_sensitive,
    ):
        item = InvestigationEvidence(
            investigation_id=investigation_id,
            recorded_by=recorded_by,
            reference=reference,
            evidence_type=evidence_type,
            description=description,
            is_sensitive=is_sensitive,
        )
        self.db.add(item)
        return item

    def get_evidence(self, investigation_id):
        return (
            self.db.query(InvestigationEvidence)
            .filter(InvestigationEvidence.investigation_id == investigation_id)
            .order_by(InvestigationEvidence.created_at.asc())
            .all()
        )

    def get_history(self, investigation_id):
        return (
            self.db.query(InvestigationHistory)
            .filter(InvestigationHistory.investigation_id == investigation_id)
            .order_by(InvestigationHistory.created_at.asc())
            .all()
        )