from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from models.risk_assessment import RiskAssessment
from models.risk_assessment_history import RiskAssessmentHistory
from repositories.risk_assessment_repository import RiskAssessmentRepository
from schemas.risk_assessment import RiskDecisionUpdate


CRITICALITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

RISK_STATUSES = {
    "OPEN",
    "ACCEPTED",
    "IN_REMEDIATION",
    "REMEDIATED",
}


def classify_risk(score: float) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def calculate_risk_score(
    asset_criticality: str,
    vulnerability_severity: str,
) -> float:
    criticality = CRITICALITY_WEIGHT.get(
        str(asset_criticality).upper()
    )
    severity = SEVERITY_WEIGHT.get(
        str(vulnerability_severity).upper()
    )

    if criticality is None:
        raise ValueError(
            f"Unsupported asset criticality: {asset_criticality}"
        )

    if severity is None:
        raise ValueError(
            f"Unsupported vulnerability severity: {vulnerability_severity}"
        )

    return round((criticality * severity / 16) * 100, 2)


class RiskAssessmentService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = RiskAssessmentRepository(db)

    def assess_asset(self, asset_id: int, actor_id: int):
        asset = self.repo.get_asset(asset_id)
        if asset is None:
            raise HTTPException(
                status_code=404,
                detail="Asset not found",
            )

        criticality = str(asset.criticality).upper()
        if criticality not in CRITICALITY_WEIGHT:
            raise HTTPException(
                status_code=422,
                detail="Asset has an unsupported criticality value",
            )

        vulnerabilities = self.repo.get_active_vulnerabilities(asset_id)

        highest_vulnerability = None
        highest_weight = 0

        for vulnerability in vulnerabilities:
            severity = str(vulnerability.severity).upper()
            weight = SEVERITY_WEIGHT.get(severity, 0)

            if weight > highest_weight:
                highest_weight = weight
                highest_vulnerability = vulnerability

        if highest_vulnerability is None:
            score = 0.0
            severity = None
            vulnerability_id = None
            details = (
                "No active linked vulnerabilities were found. "
                "Risk score is 0 under the documented scoring rules."
            )
        else:
            severity = str(highest_vulnerability.severity).upper()
            vulnerability_id = highest_vulnerability.id
            score = calculate_risk_score(criticality, severity)
            details = (
                f"Risk calculated from asset criticality {criticality} "
                f"and highest active vulnerability severity {severity}. "
                "Formula: (criticality weight × severity weight / 16) × 100."
            )

        level = classify_risk(score)

        try:
            assessment = RiskAssessment(
                asset_id=asset.id,
                highest_risk_vulnerability_id=vulnerability_id,
                assessed_by=actor_id,
                asset_criticality=criticality,
                vulnerability_severity=severity,
                risk_score=score,
                risk_level=level,
                status="OPEN",
                assessment_details=details,
            )
            self.repo.create_assessment(assessment)

            self.repo.add_history(
                RiskAssessmentHistory(
                    assessment_id=assessment.id,
                    actor_id=actor_id,
                    action="ASSESSMENT_CREATED",
                    previous_score=None,
                    new_score=score,
                    previous_level=None,
                    new_level=level,
                    details=details,
                )
            )

            self.repo.commit()
            self.db.refresh(assessment)
            return assessment
        except Exception:
            self.repo.rollback()
            raise

    def list_assessments(
        self,
        asset_id: int | None = None,
        risk_level: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ):
        if risk_level is not None:
            risk_level = risk_level.upper()
            if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise HTTPException(
                    status_code=422,
                    detail="Invalid risk level",
                )

        if status is not None:
            status = status.upper()
            if status not in RISK_STATUSES:
                raise HTTPException(
                    status_code=422,
                    detail="Invalid risk status",
                )

        return self.repo.list_assessments(
            asset_id=asset_id,
            risk_level=risk_level,
            status=status,
            limit=limit,
            offset=offset,
        )

    def get_assessment(self, assessment_id: int):
        assessment = self.repo.get_assessment(assessment_id)
        if assessment is None:
            raise HTTPException(
                status_code=404,
                detail="Risk assessment not found",
            )
        return assessment

    def get_latest_for_asset(self, asset_id: int):
        if self.repo.get_asset(asset_id) is None:
            raise HTTPException(
                status_code=404,
                detail="Asset not found",
            )

        assessment = self.repo.get_latest_for_asset(asset_id)
        if assessment is None:
            raise HTTPException(
                status_code=404,
                detail="No risk assessment exists for this asset",
            )
        return assessment

    def update_decision(
        self,
        assessment_id: int,
        payload: RiskDecisionUpdate,
        actor_id: int,
    ):
        assessment = self.get_assessment(assessment_id)
        new_status = payload.status.upper()
        details = (payload.details or "").strip()

        allowed_transitions = {
            "OPEN": {"ACCEPTED", "IN_REMEDIATION"},
            "ACCEPTED": {"OPEN", "IN_REMEDIATION"},
            "IN_REMEDIATION": {"REMEDIATED", "OPEN"},
            "REMEDIATED": {"OPEN"},
        }

        if new_status not in RISK_STATUSES:
            raise HTTPException(
                status_code=422,
                detail="Invalid risk status",
            )

        if new_status == assessment.status:
            raise HTTPException(
                status_code=409,
                detail="Risk assessment already has this status",
            )

        if new_status not in allowed_transitions.get(
            assessment.status, set()
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Status transition from {assessment.status} "
                    f"to {new_status} is not allowed"
                ),
            )

        if not details:
            raise HTTPException(
                status_code=422,
                detail="Decision details are required",
            )

        previous_status = assessment.status

        try:
            if new_status == "ACCEPTED":
                assessment.accepted_reason = details
                assessment.accepted_by = actor_id
                assessment.accepted_at = datetime.now(timezone.utc)

            elif new_status == "IN_REMEDIATION":
                assessment.remediation_notes = details
                assessment.remediated_by = None
                assessment.remediated_at = None
                assessment.accepted_reason = None
                assessment.accepted_by = None
                assessment.accepted_at = None

            elif new_status == "REMEDIATED":
                assessment.remediation_notes = details
                assessment.remediated_by = actor_id
                assessment.remediated_at = datetime.now(timezone.utc)

            elif new_status == "OPEN":
                assessment.accepted_reason = None
                assessment.accepted_by = None
                assessment.accepted_at = None
                assessment.remediated_by = None
                assessment.remediated_at = None

            assessment.status = new_status

            self.repo.add_history(
                RiskAssessmentHistory(
                    assessment_id=assessment.id,
                    actor_id=actor_id,
                    action="STATUS_CHANGED",
                    previous_score=assessment.risk_score,
                    new_score=assessment.risk_score,
                    previous_level=assessment.risk_level,
                    new_level=assessment.risk_level,
                    details=(
                        f"Status changed from {previous_status} "
                        f"to {new_status}. {details}"
                    ),
                )
            )

            self.repo.commit()
            self.db.refresh(assessment)
            return assessment
        except Exception:
            self.repo.rollback()
            raise

    def get_history(self, assessment_id: int):
        self.get_assessment(assessment_id)
        return self.repo.list_history(assessment_id)