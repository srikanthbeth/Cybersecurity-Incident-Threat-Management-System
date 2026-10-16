
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from models.alert import Alert
from models.alert_correlation_group import AlertCorrelationGroup
from models.alert_correlation_member import AlertCorrelationMember
from models.correlation_history import CorrelationHistory
from models.incident import Incident
from models.incident_alert import IncidentAlert
from models.incident_relationship import IncidentRelationship


class CorrelationRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_group(self, group_id: int):
        return self.db.get(AlertCorrelationGroup, group_id)

    def list_groups(self, limit: int = 100, offset: int = 0):
        statement = (
            select(AlertCorrelationGroup)
            .order_by(AlertCorrelationGroup.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self.db.scalars(statement).all())

    def create_group(self, group: AlertCorrelationGroup):
        self.db.add(group)
        self.db.flush()
        return group

    def get_alert(self, alert_id: int):
        return self.db.get(Alert, alert_id)

    def get_member(self, group_id: int, alert_id: int):
        statement = select(AlertCorrelationMember).where(
            AlertCorrelationMember.group_id == group_id,
            AlertCorrelationMember.alert_id == alert_id,
        )
        return self.db.scalar(statement)

    def add_member(self, member: AlertCorrelationMember):
        self.db.add(member)
        self.db.flush()
        return member

    def list_group_members(self, group_id: int):
        statement = (
            select(AlertCorrelationMember)
            .where(AlertCorrelationMember.group_id == group_id)
            .order_by(AlertCorrelationMember.created_at.asc())
        )
        return list(self.db.scalars(statement).all())

    def get_incident(self, incident_id: int):
        return self.db.get(Incident, incident_id)

    def get_incident_alert_link(self, alert_id: int):
        statement = select(IncidentAlert).where(
            IncidentAlert.alert_id == alert_id
        )
        return self.db.scalar(statement)

    def link_alert_to_incident(self, link: IncidentAlert):
        self.db.add(link)
        self.db.flush()
        return link

    def find_related_alerts(
        self,
        asset_id: int,
        category: str,
        since: datetime,
        exclude_alert_id: int | None = None,
    ):
        statement = select(Alert).where(
            Alert.asset_id == asset_id,
            func.upper(Alert.category) == category.upper(),
            Alert.detected_at >= since,
        )

        if exclude_alert_id is not None:
            statement = statement.where(Alert.id != exclude_alert_id)

        statement = statement.order_by(Alert.detected_at.desc())
        return list(self.db.scalars(statement).all())

    def find_duplicate_incidents(
        self,
        incident: Incident,
        exclude_incident_id: int,
    ):
        statement = select(Incident).where(
            Incident.id != exclude_incident_id,
            Incident.organization_id == incident.organization_id,
            func.upper(Incident.category) == str(incident.category).upper(),
        )
        return list(self.db.scalars(statement).all())

    def get_relationship(
        self,
        source_incident_id: int,
        target_incident_id: int,
    ):
        statement = select(IncidentRelationship).where(
            (
                (IncidentRelationship.source_incident_id == source_incident_id)
                & (IncidentRelationship.target_incident_id == target_incident_id)
            )
            | (
                (IncidentRelationship.source_incident_id == target_incident_id)
                & (IncidentRelationship.target_incident_id == source_incident_id)
            )
        )
        return self.db.scalar(statement)

    def create_relationship(self, relationship: IncidentRelationship):
        self.db.add(relationship)
        self.db.flush()
        return relationship

    def list_relationships(self, incident_id: int):
        statement = select(IncidentRelationship).where(
            (
                IncidentRelationship.source_incident_id == incident_id
            )
            | (
                IncidentRelationship.target_incident_id == incident_id
            )
        ).order_by(IncidentRelationship.created_at.desc())

        return list(self.db.scalars(statement).all())

    def add_history(self, history: CorrelationHistory):
        self.db.add(history)
        self.db.flush()
        return history

    def list_history(
        self,
        entity_type: str | None = None,
        entity_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ):
        statement = select(CorrelationHistory)

        if entity_type:
            statement = statement.where(
                CorrelationHistory.entity_type == entity_type.upper()
            )

        if entity_id is not None:
            statement = statement.where(
                CorrelationHistory.entity_id == entity_id
            )

        statement = (
            statement.order_by(CorrelationHistory.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self.db.scalars(statement).all())

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()
