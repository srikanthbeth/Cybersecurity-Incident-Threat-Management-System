from sqlalchemy import select
from sqlalchemy.orm import Session

from models.asset import Asset
from models.vulnerability import Vulnerability
from models.vulnerability_asset import VulnerabilityAsset
from models.risk_assessment import RiskAssessment
from models.risk_assessment_history import RiskAssessmentHistory


class RiskAssessmentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_asset(self, asset_id: int):
        return self.db.get(Asset, asset_id)

    def get_assessment(self, assessment_id: int):
        return self.db.get(RiskAssessment, assessment_id)

    def get_latest_for_asset(self, asset_id: int):
        statement = (
            select(RiskAssessment)
            .where(RiskAssessment.asset_id == asset_id)
            .order_by(
                RiskAssessment.created_at.desc(),
                RiskAssessment.id.desc(),
            )
            .limit(1)
        )
        return self.db.scalar(statement)

    def list_assessments(
        self,
        asset_id: int | None = None,
        risk_level: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ):
        statement = select(RiskAssessment)

        if asset_id is not None:
            statement = statement.where(
                RiskAssessment.asset_id == asset_id
            )

        if risk_level is not None:
            statement = statement.where(
                RiskAssessment.risk_level == risk_level
            )

        if status is not None:
            statement = statement.where(
                RiskAssessment.status == status
            )

        statement = (
            statement.order_by(
                RiskAssessment.created_at.desc(),
                RiskAssessment.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(self.db.scalars(statement).all())

    def get_active_vulnerabilities(self, asset_id: int):
        statement = (
            select(Vulnerability)
            .join(
                VulnerabilityAsset,
                VulnerabilityAsset.vulnerability_id == Vulnerability.id,
            )
            .where(VulnerabilityAsset.asset_id == asset_id)
            .where(
                Vulnerability.status.notin_(["MITIGATED", "CLOSED"])
            )
            .order_by(Vulnerability.id.asc())
        )
        return list(self.db.scalars(statement).all())

    def create_assessment(self, assessment: RiskAssessment):
        self.db.add(assessment)
        self.db.flush()
        return assessment

    def add_history(self, history: RiskAssessmentHistory):
        self.db.add(history)

    def list_history(self, assessment_id: int):
        statement = (
            select(RiskAssessmentHistory)
            .where(
                RiskAssessmentHistory.assessment_id == assessment_id
            )
            .order_by(
                RiskAssessmentHistory.created_at.asc(),
                RiskAssessmentHistory.id.asc(),
            )
        )
        return list(self.db.scalars(statement).all())

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()