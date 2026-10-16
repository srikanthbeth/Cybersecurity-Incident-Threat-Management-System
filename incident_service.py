
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.incident import Incident
from models.incident_alert import IncidentAlert
from models.user import User
from repositories.incident_repository import IncidentRepository


ALLOWED_TRANSITIONS = {
    "NEW": {"ASSIGNED", "INVESTIGATING"},
    "ASSIGNED": {"INVESTIGATING"},
    "INVESTIGATING": {"CONTAINMENT", "RESOLVED"},
    "CONTAINMENT": {"INVESTIGATING", "RESOLVED"},
    "RESOLVED": set(),
    "CLOSED": set(),
}

ASSIGNABLE_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
}


def utc_now():
    return datetime.now(timezone.utc)


class IncidentService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = IncidentRepository(db)

    def _commit(self):
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def _active_user(self, user_id: int):
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=400,
                detail="Assigned user does not exist or is inactive",
            )

        role = getattr(user.role, "value", user.role)
        if role not in ASSIGNABLE_ROLES:
            raise HTTPException(
                status_code=400,
                detail="User role is not permitted to handle incidents",
            )
        return user

    def _incident(self, incident_id: int):
        incident = self.repo.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    def create(self, payload, actor: User):
        alert = self.repo.get_alert(payload.alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        existing = self.repo.get_by_alert(payload.alert_id)
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"Alert already belongs to incident {existing.incident_number}",
            )

        if payload.assigned_to is not None:
            self._active_user(payload.assigned_to)

        incident = Incident(
            incident_number=f"INC-{uuid4().hex[:12].upper()}",
            title=payload.title,
            description=payload.description,
            category=payload.category.value,
            severity=payload.severity.value,
            status="ASSIGNED" if payload.assigned_to else "NEW",
            organization_id=alert.organization_id,
            assigned_to=payload.assigned_to,
            created_by=actor.id,
        )
        self.db.add(incident)
        self.db.flush()

        self.db.add(
            IncidentAlert(
                incident_id=incident.id,
                alert_id=alert.id,
                linked_by=actor.id,
            )
        )
        self.repo.add_history(
            incident.id,
            actor.id,
            "CREATED",
            new_value=incident.status,
            details=f"Created from alert ID {alert.id}",
        )
        if payload.assigned_to:
            self.repo.add_history(
                incident.id,
                actor.id,
                "ASSIGNED",
                new_value=str(payload.assigned_to),
                details="Initial incident assignment",
            )

        self._commit()
        self.db.refresh(incident)
        return incident

    def list(self, status=None, severity=None, search=None, skip=0, limit=20):
        return self.repo.list(
            status=status,
            severity=severity,
            search=search,
            skip=skip,
            limit=limit,
        )

    def get(self, incident_id: int):
        return self._incident(incident_id)

    def update(self, incident_id: int, payload, actor: User):
        incident = self._incident(incident_id)
        changes = payload.model_dump(exclude_unset=True)

        if not changes:
            return incident

        if incident.status == "CLOSED":
            raise HTTPException(
                status_code=409,
                detail="Closed incidents cannot be modified",
            )

        new_status = changes.get("status")
        if new_status is not None:
            new_status = getattr(new_status, "value", new_status)
            if new_status == "CLOSED":
                raise HTTPException(
                    status_code=400,
                    detail="Use the closure approval workflow to close an incident",
                )
            if new_status != incident.status:
                allowed = ALLOWED_TRANSITIONS.get(incident.status, set())
                if new_status not in allowed:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Cannot transition incident from "
                            f"{incident.status} to {new_status}"
                        ),
                    )

        if "assigned_to" in changes and changes["assigned_to"] is not None:
            self._active_user(changes["assigned_to"])

        if "resolution_details" in changes:
            if new_status != "RESOLVED" and incident.status != "RESOLVED":
                raise HTTPException(
                    status_code=400,
                    detail="Resolution details can only be set when resolving an incident",
                )
            if not changes["resolution_details"]:
                raise HTTPException(
                    status_code=400,
                    detail="Resolution details are required",
                )

        for field in ("title", "description", "category", "severity"):
            if field in changes and changes[field] is not None:
                value = changes[field]
                setattr(incident, field, getattr(value, "value", value))

        if "assigned_to" in changes:
            old_assignee = incident.assigned_to
            new_assignee = changes["assigned_to"]
            if old_assignee != new_assignee:
                incident.assigned_to = new_assignee
                self.repo.add_history(
                    incident.id,
                    actor.id,
                    "ASSIGNED",
                    old_value=str(old_assignee) if old_assignee is not None else None,
                    new_value=str(new_assignee) if new_assignee is not None else None,
                )
                if new_assignee is not None and incident.status == "NEW":
                    incident.status = "ASSIGNED"

        if "resolution_details" in changes:
            incident.resolution_details = changes["resolution_details"]

        if new_status is not None and new_status != incident.status:
            old_status = incident.status
            incident.status = new_status
            self.repo.add_history(
                incident.id,
                actor.id,
                "STATUS_CHANGED",
                old_value=old_status,
                new_value=new_status,
            )

            if new_status == "RESOLVED":
                if not incident.resolution_details:
                    raise HTTPException(
                        status_code=400,
                        detail="Resolution details are required to resolve an incident",
                    )
                incident.resolved_by = actor.id
                incident.resolved_at = utc_now()

        self._commit()
        self.db.refresh(incident)
        return incident

    def add_note(self, incident_id: int, note: str, actor: User):
        incident = self._incident(incident_id)
        if incident.status == "CLOSED":
            raise HTTPException(
                status_code=409,
                detail="Cannot add notes to a closed incident",
            )

        entry = self.repo.add_note(incident.id, actor.id, note.strip())
        self.repo.add_history(
            incident.id,
            actor.id,
            "NOTE_ADDED",
            details="Investigation note added",
        )
        self._commit()
        self.db.refresh(entry)
        return entry

    def get_notes(self, incident_id: int):
        self._incident(incident_id)
        return self.repo.get_notes(incident_id)

    def get_history(self, incident_id: int):
        self._incident(incident_id)
        return self.repo.get_history(incident_id)

    def request_closure(self, incident_id: int, details: str | None, actor: User):
        incident = self._incident(incident_id)
        if incident.status != "RESOLVED":
            raise HTTPException(
                status_code=400,
                detail="Only resolved incidents can be submitted for closure approval",
            )
        if incident.closure_requested_at and not incident.closure_approved_at:
            raise HTTPException(
                status_code=409,
                detail="Closure approval has already been requested",
            )

        incident.closure_requested_by = actor.id
        incident.closure_requested_at = utc_now()
        incident.closure_approved_by = None
        incident.closure_approved_at = None

        self.repo.add_history(
            incident.id,
            actor.id,
            "CLOSURE_REQUESTED",
            details=details or "Incident closure approval requested",
        )
        self._commit()
        self.db.refresh(incident)
        return incident

    def approve_closure(self, incident_id: int, actor: User):
        incident = self._incident(incident_id)
        if incident.status != "RESOLVED":
            raise HTTPException(
                status_code=400,
                detail="Only resolved incidents can be closed",
            )
        if not incident.closure_requested_at:
            raise HTTPException(
                status_code=400,
                detail="A closure request is required before approval",
            )
        if incident.closure_approved_at:
            raise HTTPException(
                status_code=409,
                detail="Incident closure has already been approved",
            )
        if incident.closure_requested_by == actor.id:
            raise HTTPException(
                status_code=403,
                detail="You cannot approve your own closure request",
            )

        incident.closure_approved_by = actor.id
        incident.closure_approved_at = utc_now()
        incident.status = "CLOSED"

        self.repo.add_history(
            incident.id,
            actor.id,
            "CLOSURE_APPROVED",
            old_value="RESOLVED",
            new_value="CLOSED",
            details="Incident closure approved",
        )
        self._commit()
        self.db.refresh(incident)
        return incident
