from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.investigation import Investigation
from models.investigation_evidence import InvestigationEvidence
from models.user import User
from repositories.investigation_repository import InvestigationRepository


ASSIGNABLE_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
}

EVIDENCE_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
}

ALLOWED_TRANSITIONS = {
    "OPEN": {"IN_PROGRESS", "CANCELLED"},
    "IN_PROGRESS": {"COMPLETED", "CANCELLED"},
    "COMPLETED": set(),
    "CANCELLED": set(),
}


def utc_now():
    return datetime.now(timezone.utc)


class InvestigationService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = InvestigationRepository(db)

    def _commit(self):
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def _investigation(self, investigation_id: int):
        item = self.repo.get(investigation_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return item

    def _active_assignable_user(self, user_id: int):
        user = self.db.get(User, user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=400,
                detail="Assigned user does not exist or is inactive",
            )

        role = getattr(user.role, "value", user.role)
        if role not in ASSIGNABLE_ROLES:
            raise HTTPException(
                status_code=400,
                detail="User role is not permitted to handle investigations",
            )
        return user

    def _validate_links(self, incident_id, alert_id, asset_id):
        if incident_id is not None and self.repo.get_incident(incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        if alert_id is not None and self.repo.get_alert(alert_id) is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        if asset_id is not None and self.repo.get_asset(asset_id) is None:
            raise HTTPException(status_code=404, detail="Asset not found")

    def _ensure_open(self, item):
        if item.status in {"COMPLETED", "CANCELLED"}:
            raise HTTPException(
                status_code=409,
                detail="Completed or cancelled investigations cannot be modified",
            )

    def create(self, payload, actor: User):
        self._validate_links(
            payload.incident_id, payload.alert_id, payload.asset_id
        )

        if payload.assigned_to is not None:
            self._active_assignable_user(payload.assigned_to)

        item = Investigation(
            investigation_number=f"INV-{uuid4().hex[:12].upper()}",
            title=payload.title,
            description=payload.description,
            priority=payload.priority.value,
            status="OPEN",
            incident_id=payload.incident_id,
            alert_id=payload.alert_id,
            asset_id=payload.asset_id,
            assigned_to=payload.assigned_to,
            created_by=actor.id,
        )
        self.db.add(item)
        self.db.flush()

        self.repo.add_history(
            item.id,
            actor.id,
            "CREATED",
            details="Investigation created",
        )
        if item.assigned_to is not None:
            self.repo.add_history(
                item.id,
                actor.id,
                "ASSIGNED",
                details=f"Assigned to user ID {item.assigned_to}",
            )

        self._commit()
        self.db.refresh(item)
        return item

    def list(self, status=None, priority=None, search=None, skip=0, limit=20):
        return self.repo.list(
            status=status,
            priority=priority,
            search=search,
            skip=skip,
            limit=limit,
        )

    def get(self, investigation_id: int):
        return self._investigation(investigation_id)

    def update(self, investigation_id: int, payload, actor: User):
        item = self._investigation(investigation_id)
        changes = payload.model_dump(exclude_unset=True)

        if not changes:
            return item

        self._ensure_open(item)

        new_status = changes.get("status")
        if new_status is not None:
            new_status = getattr(new_status, "value", new_status)
            if new_status != item.status:
                allowed = ALLOWED_TRANSITIONS.get(item.status, set())
                if new_status not in allowed:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Cannot transition investigation from "
                            f"{item.status} to {new_status}"
                        ),
                    )

        if "assigned_to" in changes and changes["assigned_to"] is not None:
            self._active_assignable_user(changes["assigned_to"])

        for field in ("title", "description", "priority"):
            if field in changes and changes[field] is not None:
                value = changes[field]
                setattr(item, field, getattr(value, "value", value))

        if "assigned_to" in changes:
            old_assignee = item.assigned_to
            new_assignee = changes["assigned_to"]
            if old_assignee != new_assignee:
                item.assigned_to = new_assignee
                self.repo.add_history(
                    item.id,
                    actor.id,
                    "ASSIGNED",
                    details=f"Assignment changed from {old_assignee} to {new_assignee}",
                )

        if new_status is not None and new_status != item.status:
            old_status = item.status
            item.status = new_status
            self.repo.add_history(
                item.id,
                actor.id,
                "STATUS_CHANGED",
                details=f"Status changed from {old_status} to {new_status}",
            )
            if new_status == "COMPLETED":
                item.completed_at = utc_now()

        self._commit()
        self.db.refresh(item)
        return item

    def add_note(self, investigation_id: int, note: str, actor: User):
        item = self._investigation(investigation_id)
        self._ensure_open(item)

        entry = self.repo.add_note(item.id, actor.id, note.strip())
        self.repo.add_history(
            item.id,
            actor.id,
            "NOTE_ADDED",
            details="Investigation note recorded",
        )
        self._commit()
        self.db.refresh(entry)
        return entry

    def get_notes(self, investigation_id: int):
        self._investigation(investigation_id)
        return self.repo.get_notes(investigation_id)

    def add_evidence(self, investigation_id: int, payload, actor: User):
        item = self._investigation(investigation_id)
        self._ensure_open(item)

        entry = self.repo.add_evidence(
            investigation_id=item.id,
            recorded_by=actor.id,
            reference=payload.reference.strip(),
            evidence_type=payload.evidence_type.value,
            description=payload.description.strip(),
            is_sensitive=payload.is_sensitive,
        )
        self.repo.add_history(
            item.id,
            actor.id,
            "EVIDENCE_ADDED",
            details=f"Evidence reference recorded; sensitive={payload.is_sensitive}",
        )
        self._commit()
        self.db.refresh(entry)
        return entry

    def get_evidence(self, investigation_id: int, actor: User):
        self._investigation(investigation_id)
        items = self.repo.get_evidence(investigation_id)
        role = getattr(actor.role, "value", actor.role)

        if role not in EVIDENCE_ROLES:
            items = [item for item in items if not item.is_sensitive]

        return items

    def get_history(self, investigation_id: int):
        self._investigation(investigation_id)
        return self.repo.get_history(investigation_id)