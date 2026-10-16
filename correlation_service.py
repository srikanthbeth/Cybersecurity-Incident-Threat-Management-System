
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.alert import Alert
from models.alert_correlation_group import AlertCorrelationGroup
from models.alert_correlation_member import AlertCorrelationMember
from models.correlation_history import CorrelationHistory
from models.incident_alert import IncidentAlert
from models.incident_relationship import IncidentRelationship
from repositories.correlation_repository import CorrelationRepository


class CorrelationService:
    def __init__(self, db: Session):
        self.db = db
        self.repository = CorrelationRepository(db)

    @staticmethod
    def _user_id(user) -> int:
        user_id = getattr(user, "id", None)
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid user")
        return user_id

    @staticmethod
    def _normalized_title(title: str | None) -> str:
        return re.sub(r"\s+", " ", (title or "").strip().lower())

    def _history(
        self,
        user_id: int,
        action: str,
        entity_type: str,
        entity_id: int,
        details: str,
    ):
        self.repository.add_history(
            CorrelationHistory(
                actor_id=user_id,
                action=action,
                entity_type=entity_type.upper(),
                entity_id=entity_id,
                details=details,
            )
        )

    def create_group(self, data, user):
        user_id = self._user_id(user)

        try:
            group = AlertCorrelationGroup(
                name=data.name.strip(),
                description=data.description,
                rule_type=data.rule_type,
                status="ACTIVE",
                created_by=user_id,
            )
            self.repository.create_group(group)

            self._history(
                user_id,
                "GROUP_CREATED",
                "GROUP",
                group.id,
                f"Created correlation group '{group.name}'",
            )

            self.repository.commit()
            self.db.refresh(group)
            return group
        except Exception:
            self.repository.rollback()
            raise

    def list_groups(self, limit: int = 100, offset: int = 0):
        return self.repository.list_groups(limit=limit, offset=offset)

    def add_alert_to_group(self, group_id: int, alert_id: int, user):
        user_id = self._user_id(user)
        group = self.repository.get_group(group_id)

        if group is None:
            raise HTTPException(status_code=404, detail="Correlation group not found")

        if group.status != "ACTIVE":
            raise HTTPException(status_code=409, detail="Correlation group is inactive")

        alert = self.repository.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        existing = self.repository.get_member(group_id, alert_id)
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="Alert is already in this correlation group",
            )

        try:
            member = AlertCorrelationMember(
                group_id=group_id,
                alert_id=alert_id,
                added_by=user_id,
            )
            self.repository.add_member(member)

            self._history(
                user_id,
                "ALERT_ADDED_TO_GROUP",
                "GROUP",
                group_id,
                f"Alert {alert_id} added to correlation group {group_id}",
            )

            self.repository.commit()
            self.db.refresh(member)
            return member
        except Exception:
            self.repository.rollback()
            raise

    def list_group_alerts(self, group_id: int):
        if self.repository.get_group(group_id) is None:
            raise HTTPException(status_code=404, detail="Correlation group not found")

        return self.repository.list_group_members(group_id)

    def correlate_alert(self, alert_id: int, window_minutes: int = 60):
        if not 1 <= window_minutes <= 10080:
            raise HTTPException(
                status_code=422,
                detail="window_minutes must be between 1 and 10080",
            )

        alert = self.repository.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        if alert.asset_id is None:
            return {
                "asset_id": None,
                "category": str(alert.category),
                "window_minutes": window_minutes,
                "matching_alert_ids": [],
                "suggested_incident_id": None,
                "reason": "This alert has no associated asset",
            }

        detected_at = alert.detected_at
        if detected_at.tzinfo is None:
            detected_at = detected_at.replace(tzinfo=timezone.utc)

        since = detected_at - timedelta(minutes=window_minutes)

        candidates = self.repository.find_related_alerts(
            asset_id=alert.asset_id,
            category=str(alert.category),
            since=since,
            exclude_alert_id=alert.id,
        )

        candidates = [
            candidate
            for candidate in candidates
            if candidate.organization_id == alert.organization_id
        ]

        linked_incident = self.repository.get_incident_alert_link(alert.id)
        suggested_incident_id = (
            linked_incident.incident_id if linked_incident else None
        )

        self.db.commit()

        return {
            "asset_id": alert.asset_id,
            "category": str(alert.category),
            "window_minutes": window_minutes,
            "matching_alert_ids": [candidate.id for candidate in candidates],
            "suggested_incident_id": suggested_incident_id,
            "reason": (
                "Alerts share the same asset and category within the time window"
                if candidates
                else "No matching alerts found in the selected time window"
            ),
        }

    def link_alert_to_incident(
        self,
        incident_id: int,
        alert_id: int,
        user,
    ):
        user_id = self._user_id(user)
        incident = self.repository.get_incident(incident_id)

        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        alert = self.repository.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        if alert.organization_id != incident.organization_id:
            raise HTTPException(
                status_code=400,
                detail="Alert and incident must belong to the same organization",
            )

        existing_link = self.repository.get_incident_alert_link(alert_id)
        if existing_link is not None:
            if existing_link.incident_id == incident_id:
                raise HTTPException(
                    status_code=409,
                    detail="Alert is already linked to this incident",
                )
            raise HTTPException(
                status_code=409,
                detail="Alert is already linked to another incident",
            )

        try:
            link = IncidentAlert(
                incident_id=incident_id,
                alert_id=alert_id,
                linked_by=user_id,
            )
            self.repository.link_alert_to_incident(link)

            self._history(
                user_id,
                "ALERT_LINKED_TO_INCIDENT",
                "INCIDENT",
                incident_id,
                f"Alert {alert_id} linked to incident {incident_id}",
            )

            self.repository.commit()
            self.db.refresh(link)
            return link
        except Exception:
            self.repository.rollback()
            raise

    def find_duplicate_incidents(self, incident_id: int, user):
        user_id = self._user_id(user)
        incident = self.repository.get_incident(incident_id)

        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        candidates = self.repository.find_duplicate_incidents(
            incident,
            exclude_incident_id=incident_id,
        )

        normalized_title = self._normalized_title(incident.title)
        matches = []

        for candidate in candidates:
            if self._normalized_title(candidate.title) != normalized_title:
                continue

            matches.append(
                {
                    "incident_id": candidate.id,
                    "incident_number": candidate.incident_number,
                    "title": candidate.title,
                    "category": str(candidate.category),
                    "severity": str(candidate.severity),
                    "status": str(candidate.status),
                    "matching_reasons": [
                        "Same organization",
                        "Same category",
                        "Same normalized title",
                    ],
                }
            )

        self._history(
            user_id,
            "DUPLICATE_CHECKED",
            "INCIDENT",
            incident_id,
            f"Potential duplicate check found {len(matches)} matching incident(s)",
        )
        self.repository.commit()

        return matches

    def relate_incidents(
        self,
        source_incident_id: int,
        data,
        user,
    ):
        user_id = self._user_id(user)
        target_incident_id = data.target_incident_id

        if source_incident_id == target_incident_id:
            raise HTTPException(
                status_code=400,
                detail="An incident cannot be related to itself",
            )

        source = self.repository.get_incident(source_incident_id)
        target = self.repository.get_incident(target_incident_id)

        if source is None or target is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        if source.organization_id != target.organization_id:
            raise HTTPException(
                status_code=400,
                detail="Related incidents must belong to the same organization",
            )

        if self.repository.get_relationship(
            source_incident_id,
            target_incident_id,
        ):
            raise HTTPException(
                status_code=409,
                detail="A relationship already exists between these incidents",
            )

        try:
            relationship = IncidentRelationship(
                source_incident_id=source_incident_id,
                target_incident_id=target_incident_id,
                relationship_type=data.relationship_type,
                details=data.details,
                created_by=user_id,
            )
            self.repository.create_relationship(relationship)

            self._history(
                user_id,
                "INCIDENTS_RELATED",
                "INCIDENT",
                source_incident_id,
                (
                    f"Related incident {target_incident_id} using "
                    f"{data.relationship_type}"
                ),
            )

            self.repository.commit()
            self.db.refresh(relationship)
            return relationship
        except Exception:
            self.repository.rollback()
            raise

    def list_related_incidents(self, incident_id: int):
        if self.repository.get_incident(incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        return self.repository.list_relationships(incident_id)

    def list_history(
        self,
        entity_type: str | None = None,
        entity_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ):
        return self.repository.list_history(
            entity_type=entity_type,
            entity_id=entity_id,
            limit=limit,
            offset=offset,
        )
