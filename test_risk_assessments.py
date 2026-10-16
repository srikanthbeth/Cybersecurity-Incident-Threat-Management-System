
import os
import uuid

os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://postgres:Srik8499@localhost:5433/"
    "cybersecurity_incident_threat_test"
)

import pytest
from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from models.user import User
from services.risk_assessment_service import (
    calculate_risk_score,
    classify_risk,
)

client = TestClient(app)
PASSWORD = "TestPassword123!"


def unique_email():
    return f"risk_{uuid.uuid4().hex[:12]}@example.com"


def register_and_login(role="SUPER_ADMIN"):
    email = unique_email()

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Risk Assessment Tester",
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code in (200, 201), response.text

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 200, response.text

    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def create_organization(headers):
    code = f"RISK-{uuid.uuid4().hex[:8].upper()}"

    response = client.post(
        "/api/v1/organizations",
        headers=headers,
        json={
            "name": f"Risk Test {code}",
            "code": code,
            "description": "Risk assessment integration test",
            "industry": "Technology",
            "contact_email": f"{code.lower()}@example.com",
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["id"]


def create_asset(headers, organization_id, criticality="CRITICAL"):
    tag = f"RISK-{uuid.uuid4().hex[:8].upper()}"

    response = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "organization_id": organization_id,
            "asset_tag": tag,
            "name": f"Risk Test Asset {tag}",
            "asset_type": "SERVER",
            "description": "Asset for risk assessment tests",
            "ip_address": "192.0.2.10",
            "hostname": tag.lower(),
            "operating_system": "Linux",
            "criticality": criticality,
            "status": "ACTIVE",
            "location": "Test environment",
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["id"]


def create_vulnerability(
    headers, organization_id, asset_id, severity="CRITICAL"
):
    reference = f"RISK-VULN-{uuid.uuid4().hex[:10].upper()}"

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers,
        json={
            "vulnerability_ref": reference,
            "title": "Risk assessment test vulnerability",
            "description": "A test vulnerability for risk scoring",
            "cve_id": None,
            "severity": severity,
            "cvss_score": 9.0,
            "organization_id": organization_id,
            "remediation_recommendation": (
                "Apply the latest security patch"
            ),
            "asset_ids": [asset_id],
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["id"]


def prepare_asset(criticality="CRITICAL", role="SUPER_ADMIN"):
    headers = register_and_login(role)
    organization_id = create_organization(headers)
    asset_id = create_asset(headers, organization_id, criticality)
    return headers, organization_id, asset_id


@pytest.mark.parametrize(
    "criticality,severity,expected",
    [
        ("LOW", "LOW", 6.25),
        ("LOW", "CRITICAL", 25.0),
        ("MEDIUM", "MEDIUM", 25.0),
        ("HIGH", "HIGH", 56.25),
        ("CRITICAL", "CRITICAL", 100.0),
    ],
)
def test_risk_score_formula(criticality, severity, expected):
    assert calculate_risk_score(criticality, severity) == expected


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, "LOW"),
        (24.99, "LOW"),
        (25, "MEDIUM"),
        (49.99, "MEDIUM"),
        (50, "HIGH"),
        (74.99, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_risk_classification_boundaries(score, expected):
    assert classify_risk(score) == expected


def test_assessment_without_vulnerabilities_is_low():
    headers, _, asset_id = prepare_asset("CRITICAL")

    response = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["asset_id"] == asset_id
    assert data["risk_score"] == 0
    assert data["risk_level"] == "LOW"
    assert data["highest_risk_vulnerability_id"] is None


def test_assessment_uses_highest_active_vulnerability():
    headers, organization_id, asset_id = prepare_asset("CRITICAL")
    vulnerability_id = create_vulnerability(
        headers, organization_id, asset_id, "CRITICAL"
    )

    response = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["highest_risk_vulnerability_id"] == vulnerability_id
    assert data["risk_score"] == 100
    assert data["risk_level"] == "CRITICAL"


def test_assessment_requires_authentication():
    response = client.post(
        "/api/v1/risk-assessments/assets/1/assess"
    )
    assert response.status_code in (401, 403)


def test_viewer_cannot_assess_asset():
    _, _, asset_id = prepare_asset(
        "HIGH", role="SUPER_ADMIN"
    )
    viewer_headers = register_and_login("VIEWER")

    response = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=viewer_headers,
    )

    assert response.status_code == 403


def test_missing_asset_returns_404():
    headers = register_and_login()

    response = client.post(
        "/api/v1/risk-assessments/assets/999999999/assess",
        headers=headers,
    )
    assert response.status_code == 404


def test_assessment_history_records_creation():
    headers, _, asset_id = prepare_asset("HIGH")

    response = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assessment_id = response.json()["id"]

    history_response = client.get(
        f"/api/v1/risk-assessments/{assessment_id}/history",
        headers=headers,
    )

    assert history_response.status_code == 200
    history = history_response.json()
    assert len(history) >= 1
    assert history[0]["action"] == "ASSESSMENT_CREATED"


def test_risk_acceptance_is_tracked():
    headers, _, asset_id = prepare_asset("HIGH")

    response = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assessment_id = response.json()["id"]

    decision = client.patch(
        f"/api/v1/risk-assessments/{assessment_id}/decision",
        headers=headers,
        json={
            "status": "ACCEPTED",
            "details": (
                "Accepted for this test with documented approval"
            ),
        },
    )

    assert decision.status_code == 200, decision.text
    assert decision.json()["status"] == "ACCEPTED"
    assert decision.json()["accepted_reason"]


def test_remediation_workflow_is_tracked():
    headers, _, asset_id = prepare_asset("HIGH")

    response = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assessment_id = response.json()["id"]

    remediation = client.patch(
        f"/api/v1/risk-assessments/{assessment_id}/decision",
        headers=headers,
        json={
            "status": "IN_REMEDIATION",
            "details": (
                "Security team is applying the approved remediation"
            ),
        },
    )

    assert remediation.status_code == 200, remediation.text
    assert remediation.json()["status"] == "IN_REMEDIATION"

    completed = client.patch(
        f"/api/v1/risk-assessments/{assessment_id}/decision",
        headers=headers,
        json={
            "status": "REMEDIATED",
            "details": "Patch applied and remediation verified",
        },
    )

    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "REMEDIATED"


def test_same_status_transition_is_rejected():
    headers, _, asset_id = prepare_asset("HIGH")

    response = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assessment_id = response.json()["id"]

    decision = client.patch(
        f"/api/v1/risk-assessments/{assessment_id}/decision",
        headers=headers,
        json={
            "status": "OPEN",
            "details": "Attempting to set the existing status",
        },
    )
    assert decision.status_code == 409


def test_latest_assessment_endpoint():
    headers, _, asset_id = prepare_asset("MEDIUM")

    created = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )
    assert created.status_code == 201, created.text

    latest = client.get(
        f"/api/v1/risk-assessments/assets/{asset_id}/latest",
        headers=headers,
    )

    assert latest.status_code == 200
    assert latest.json()["id"] == created.json()["id"]


def test_list_assessments_filter_by_risk_level():
    headers, _, asset_id = prepare_asset("CRITICAL")

    created = client.post(
        f"/api/v1/risk-assessments/assets/{asset_id}/assess",
        headers=headers,
    )
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/risk-assessments?risk_level=LOW",
        headers=headers,
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
