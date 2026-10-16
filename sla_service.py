
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from models.incident_sla import IncidentSLA
from models.sla_policy import SLAPolicy
from repositories.sla_repository import SLARepository
from schemas.sla import (
    IncidentSLARead,
    SLADeadlineItem,
    SLAEventUpdate,
    SLAPolicyCreate,
    SLAPolicyUpdate,
    SLASummary,
)


APPROACHING_WINDOW_MINUTES = 30


class SLAService:
    def __init__(self, db: Session):
        self.db = db
        self.repository = SLARepository(db)

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _elapsed_minutes(start: datetime, end: datetime) -> int:
        return max(
            0,
            int(
                (
                    SLAService._utc(end) - SLAService._utc(start)
                ).total_seconds() // 60
            ),
        )

    @staticmethod
    def _severity(value: str) -> str:
        return str(value).upper().replace(" ", "_")

    @staticmethod
    def _incident_is_resolved(incident) -> bool:
        return str(incident.status).upper().split(".")[-1] in {
            "RESOLVED",
            "CLOSED",
        }

    def create_policy(self, payload: SLAPolicyCreate) -> SLAPolicy:
        severity = self._severity(payload.severity)

        existing = self.repository.get_policy_by_severity(severity)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"An active SLA policy already exists for {severity}",
            )

        # The database has a unique constraint on severity, including
        # inactive policies. Do not create a duplicate inactive policy either.
        duplicate = (
            self.db.query(SLAPolicy)
            .filter(SLAPolicy.severity == severity)
            .first()
        )
        if duplicate:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"An SLA policy already exists for {severity}",
            )

        policy = SLAPolicy(
            severity=severity,
            acknowledgment_minutes=payload.acknowledgment_minutes,
            investigation_minutes=payload.investigation_minutes,
            resolution_minutes=payload.resolution_minutes,
            escalation_after_minutes=payload.escalation_after_minutes,
            is_active=payload.is_active,
        )

        try:
            self.repository.save(policy)
            self.repository.commit()
            self.db.refresh(policy)
            return policy
        except Exception:
            self.repository.rollback()
            raise

    def list_policies(self):
        return self.repository.list_policies()

    def get_policy(self, policy_id: int) -> SLAPolicy:
        policy = self.repository.get_policy(policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="SLA policy not found")
        return policy

    def update_policy(
        self, policy_id: int, payload: SLAPolicyUpdate
    ) -> SLAPolicy:
        policy = self.get_policy(policy_id)

        for field, value in payload.model_dump(
            exclude_unset=True
        ).items():
            if value is not None:
                setattr(policy, field, value)

        try:
            self.repository.commit()
            self.db.refresh(policy)
            return policy
        except Exception:
            self.repository.rollback()
            raise

    def ensure_incident_sla(self, incident_id: int) -> IncidentSLA:
        existing = self.repository.get_incident_sla(incident_id)
        if existing:
            self.refresh_status(existing)
            self.repository.commit()
            self.db.refresh(existing)
            return existing

        incident = self.repository.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        severity = self._severity(incident.severity)
        policy = self.repository.get_policy_by_severity(severity)

        if not policy:
            raise HTTPException(
                status_code=409,
                detail=f"No active SLA policy configured for {severity}",
            )

        started_at = self._utc(incident.created_at or self._now())

        sla = IncidentSLA(
            incident_id=incident.id,
            policy_id=policy.id,
            severity=severity,
            started_at=started_at,
            acknowledgment_deadline=started_at
            + timedelta(minutes=policy.acknowledgment_minutes),
            investigation_deadline=started_at
            + timedelta(minutes=policy.investigation_minutes),
            resolution_deadline=started_at
            + timedelta(minutes=policy.resolution_minutes),
            breach_status="ON_TRACK",
            escalation_status="NOT_REQUIRED",
        )

        try:
            self.repository.save(sla)
            self.refresh_status(sla)
            self.repository.commit()
            self.db.refresh(sla)
            return sla
        except Exception:
            self.repository.rollback()
            raise

    def refresh_status(self, sla: IncidentSLA) -> IncidentSLA:
        now = self._now()
        incident = self.repository.get_incident(sla.incident_id)

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        if sla.acknowledged_at:
            sla.actual_response_minutes = self._elapsed_minutes(
                sla.started_at, sla.acknowledged_at
            )
            sla.acknowledgment_breached = (
                self._utc(sla.acknowledged_at)
                > self._utc(sla.acknowledgment_deadline)
            )
        else:
            sla.acknowledgment_breached = (
                now > self._utc(sla.acknowledgment_deadline)
            )

        if sla.investigation_started_at:
            sla.actual_investigation_minutes = self._elapsed_minutes(
                sla.started_at, sla.investigation_started_at
            )
            sla.investigation_breached = (
                self._utc(sla.investigation_started_at)
                > self._utc(sla.investigation_deadline)
            )
        else:
            sla.investigation_breached = (
                now > self._utc(sla.investigation_deadline)
            )

        resolved_at = sla.resolved_at
        if not resolved_at and self._incident_is_resolved(incident):
            resolved_at = getattr(incident, "resolved_at", None) or now

        if resolved_at:
            sla.actual_resolution_minutes = self._elapsed_minutes(
                sla.started_at, resolved_at
            )
            sla.resolution_breached = (
                self._utc(resolved_at)
                > self._utc(sla.resolution_deadline)
            )
        else:
            sla.resolution_breached = (
                now > self._utc(sla.resolution_deadline)
            )

        if resolved_at:
            sla.breach_status = "RESOLVED"
        elif (
            sla.acknowledgment_breached
            or sla.investigation_breached
            or sla.resolution_breached
        ):
            sla.breach_status = "BREACHED"
        else:
            deadlines = []
            if not sla.acknowledged_at:
                deadlines.append(sla.acknowledgment_deadline)
            if not sla.investigation_started_at:
                deadlines.append(sla.investigation_deadline)
            if not resolved_at:
                deadlines.append(sla.resolution_deadline)

            approaching = any(
                timedelta(0)
                <= self._utc(deadline) - now
                <= timedelta(minutes=APPROACHING_WINDOW_MINUTES)
                for deadline in deadlines
            )
            sla.breach_status = "APPROACHING" if approaching else "ON_TRACK"

        if sla.escalation_status != "ESCALATED":
            policy = (
                self.repository.get_policy(sla.policy_id)
                if sla.policy_id
                else None
            )
            escalation_minutes = (
                policy.escalation_after_minutes if policy else 15
            )

            breached_deadlines = []
            if sla.acknowledgment_breached:
                breached_deadlines.append(sla.acknowledgment_deadline)
            if sla.investigation_breached:
                breached_deadlines.append(sla.investigation_deadline)
            if sla.resolution_breached:
                breached_deadlines.append(sla.resolution_deadline)

            escalation_due = any(
                now
                >= self._utc(deadline)
                + timedelta(minutes=escalation_minutes)
                for deadline in breached_deadlines
            )

            if escalation_due:
                sla.escalation_status = "PENDING"
            elif not breached_deadlines:
                sla.escalation_status = "NOT_REQUIRED"

        return sla

    def get_incident_sla(self, incident_id: int) -> IncidentSLA:
        sla = self.ensure_incident_sla(incident_id)
        self.refresh_status(sla)
        self.repository.commit()
        self.db.refresh(sla)
        return sla

    def record_event(
        self, incident_id: int, payload: SLAEventUpdate
    ) -> IncidentSLA:
        sla = self.ensure_incident_sla(incident_id)
        incident = self.repository.get_incident(incident_id)
        now = self._now()

        if payload.event == "ACKNOWLEDGED":
            if sla.acknowledged_at:
                raise HTTPException(
                    status_code=409,
                    detail="Incident has already been acknowledged",
                )
            sla.acknowledged_at = now

        elif payload.event == "INVESTIGATION_STARTED":
            if sla.investigation_started_at:
                raise HTTPException(
                    status_code=409,
                    detail="Investigation has already been started",
                )
            sla.investigation_started_at = now

        elif payload.event == "RESOLVED":
            if sla.resolved_at:
                raise HTTPException(
                    status_code=409,
                    detail="Incident SLA is already resolved",
                )
            if not self._incident_is_resolved(incident):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Resolve the incident through the incident API "
                        "before recording the SLA resolution event"
                    ),
                )
            sla.resolved_at = (
                getattr(incident, "resolved_at", None) or now
            )

        try:
            self.refresh_status(sla)
            self.repository.commit()
            self.db.refresh(sla)
            return sla
        except Exception:
            self.repository.rollback()
            raise

    def mark_escalated(self, incident_id: int) -> IncidentSLA:
        sla = self.ensure_incident_sla(incident_id)
        self.refresh_status(sla)

        if sla.escalation_status != "PENDING":
            raise HTTPException(
                status_code=409,
                detail="This incident has no pending SLA escalation",
            )

        sla.escalation_status = "ESCALATED"
        sla.escalated_at = self._now()

        try:
            self.repository.commit()
            self.db.refresh(sla)
            return sla
        except Exception:
            self.repository.rollback()
            raise

    def list_deadlines(
        self,
        kind: str,
        within_minutes: int = APPROACHING_WINDOW_MINUTES,
    ) -> list[SLADeadlineItem]:
        now = self._now()
        result = []

        for sla in self.repository.list_incident_slas():
            incident = self.repository.get_incident(sla.incident_id)
            if not incident:
                continue

            self.refresh_status(sla)

            deadlines = [
                (
                    "ACKNOWLEDGMENT",
                    sla.acknowledgment_deadline,
                    sla.acknowledged_at is not None,
                    sla.acknowledgment_breached,
                ),
                (
                    "INVESTIGATION",
                    sla.investigation_deadline,
                    sla.investigation_started_at is not None,
                    sla.investigation_breached,
                ),
                (
                    "RESOLUTION",
                    sla.resolution_deadline,
                    sla.resolved_at is not None
                    or self._incident_is_resolved(incident),
                    sla.resolution_breached,
                ),
            ]

            for deadline_type, deadline, completed, breached in deadlines:
                if completed:
                    continue

                remaining = int(
                    (
                        self._utc(deadline) - now
                    ).total_seconds() // 60
                )

                if kind == "breached":
                    include = breached
                else:
                    include = (
                        not breached
                        and 0 <= remaining <= within_minutes
                    )

                if include:
                    result.append(
                        SLADeadlineItem(
                            incident_id=incident.id,
                            incident_title=incident.title,
                            severity=sla.severity,
                            deadline_type=deadline_type,
                            deadline=deadline,
                            minutes_remaining=remaining,
                            breach_status=sla.breach_status,
                            escalation_status=sla.escalation_status,
                        )
                    )

        self.repository.commit()
        result.sort(key=lambda item: item.minutes_remaining)
        return result

    def get_summary(self) -> SLASummary:
        records = self.repository.list_incident_slas()
        now = self._now()

        for sla in records:
            self.refresh_status(sla)

        self.repository.commit()

        return SLASummary(
            total_tracked=len(records),
            on_track=sum(
                item.breach_status == "ON_TRACK" for item in records
            ),
            approaching_deadline=sum(
                item.breach_status == "APPROACHING" for item in records
            ),
            breached=sum(
                item.breach_status == "BREACHED" for item in records
            ),
            resolved=sum(
                item.breach_status == "RESOLVED" for item in records
            ),
            escalation_pending=sum(
                item.escalation_status == "PENDING" for item in records
            ),
            escalated=sum(
                item.escalation_status == "ESCALATED" for item in records
            ),
        )
