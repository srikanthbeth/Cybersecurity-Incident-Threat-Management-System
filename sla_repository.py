
from sqlalchemy.orm import Session

from models.incident import Incident
from models.incident_sla import IncidentSLA
from models.sla_policy import SLAPolicy


class SLARepository:
    def __init__(self, db: Session):
        self.db = db

    def get_policy_by_severity(self, severity: str):
        return (
            self.db.query(SLAPolicy)
            .filter(
                SLAPolicy.severity == severity.upper(),
                SLAPolicy.is_active.is_(True),
            )
            .first()
        )

    def get_policy(self, policy_id: int):
        return (
            self.db.query(SLAPolicy)
            .filter(SLAPolicy.id == policy_id)
            .first()
        )

    def list_policies(self):
        return (
            self.db.query(SLAPolicy)
            .order_by(SLAPolicy.severity.asc())
            .all()
        )

    def get_incident(self, incident_id: int):
        return (
            self.db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

    def get_incident_sla(self, incident_id: int):
        return (
            self.db.query(IncidentSLA)
            .filter(IncidentSLA.incident_id == incident_id)
            .first()
        )

    def get_sla_by_id(self, sla_id: int):
        return (
            self.db.query(IncidentSLA)
            .filter(IncidentSLA.id == sla_id)
            .first()
        )

    def list_incident_slas(self):
        return self.db.query(IncidentSLA).all()

    def save(self, record):
        self.db.add(record)
        self.db.flush()
        return record

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()
