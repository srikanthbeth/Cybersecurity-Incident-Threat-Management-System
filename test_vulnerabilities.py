
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://postgres:Srik8499@localhost:5433/"
    "cybersecurity_incident_threat_test"
)
os.environ["ENVIRONMENT"] = "development"

from database import Base, SessionLocal, engine
from main import app
from models.user import User

client = TestClient(app)
PASSWORD = "StrongPassword123!"


def unique_value(prefix="TEST"):
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def cleanup_database():
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE vulnerability_history, "
                "vulnerability_assets, vulnerabilities "
                "RESTART IDENTITY CASCADE"
            )
        )


def register_user(role="SUPER_ADMIN"):
    email = f"{uuid.uuid4().hex}@example.com"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Vulnerability Test User",
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code in (200, 201), response.text

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        user.is_active = True
        db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text

    return {
        "email": email,
        "token": response.json()["access_token"],
    }


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_organization(token):
    response = client.post(
        "/api/v1/organizations",
        headers=headers(token),
        json={
            "name": unique_value("Organization"),
            "code": unique_value("ORG"),
            "description": "Organization for vulnerability integration tests",
            "industry": "Technology",
            "contact_email": f"{uuid.uuid4().hex}@example.com",
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()


def create_asset(token, organization_id):
    response = client.post(
        "/api/v1/assets",
        headers=headers(token),
        json={
            "organization_id": organization_id,
            "asset_tag": unique_value("ASSET"),
            "name": unique_value("Test Server"),
            "asset_type": "SERVER",
            "description": "Asset for vulnerability tests",
            "ip_address": "10.20.30.40",
            "hostname": unique_value("HOST"),
            "operating_system": "Linux",
            "criticality": "HIGH",
            "status": "ACTIVE",
            "location": "Test Environment",
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()


def setup_context(role="SUPER_ADMIN", with_asset=False):
    admin = register_user("SUPER_ADMIN")

    if role == "SUPER_ADMIN":
        actor = admin
    else:
        actor = register_user(role)

    organization = create_organization(admin["token"])
    asset = None

    if with_asset:
        asset = create_asset(admin["token"], organization["id"])

    return actor, admin, organization, asset


def vulnerability_payload(organization_id, **overrides):
    payload = {
        "vulnerability_ref": unique_value("VULN"),
        "title": "Outdated OpenSSL version",
        "description": (
            "The affected server is running an outdated OpenSSL version."
        ),
        "cve_id": None,
        "severity": "HIGH",
        "cvss_score": 8.1,
        "organization_id": organization_id,
        "remediation_recommendation": (
            "Upgrade OpenSSL to a supported patched version."
        ),
        "remediation_deadline": (
            datetime.now(timezone.utc) + timedelta(days=14)
        ).isoformat(),
        "asset_ids": [],
    }
    payload.update(overrides)
    return payload


def create_vulnerability(token, organization_id, **overrides):
    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(token),
        json=vulnerability_payload(organization_id, **overrides),
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture(autouse=True)
def clean_vulnerability_tables():
    Base.metadata.create_all(bind=engine)
    cleanup_database()
    yield
    cleanup_database()


def test_create_vulnerability_success():
    actor, _, organization, asset = setup_context(with_asset=True)

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"],
            asset_ids=[asset["id"]],
            cve_id="CVE-2024-12345",
        ),
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["vulnerability_ref"].startswith("VULN-")
    assert data["cve_id"] == "CVE-2024-12345"
    assert data["severity"] == "HIGH"
    assert data["cvss_score"] == 8.1
    assert data["status"] == "OPEN"
    assert data["organization_id"] == organization["id"]


def test_create_vulnerability_requires_authentication():
    _, _, organization, _ = setup_context()

    response = client.post(
        "/api/v1/vulnerabilities",
        json=vulnerability_payload(organization["id"]),
    )

    assert response.status_code == 401


def test_viewer_cannot_create_vulnerability():
    actor, _, organization, _ = setup_context("VIEWER")

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(organization["id"]),
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "role",
    ["SUPER_ADMIN", "SECURITY_MANAGER", "SECURITY_ANALYST"],
)
def test_authorized_roles_can_create_vulnerability(role):
    actor, _, organization, _ = setup_context(role)

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(organization["id"]),
    )

    assert response.status_code == 201, response.text


def test_invalid_cve_identifier_is_rejected():
    actor, _, organization, _ = setup_context()

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"], cve_id="INVALID-CVE"
        ),
    )

    assert response.status_code == 422


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_cvss_score_out_of_range_is_rejected(score):
    actor, _, organization, _ = setup_context()

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"], cvss_score=score
        ),
    )

    assert response.status_code == 422


@pytest.mark.parametrize("score", [0, 0.0, 10, 10.0])
def test_cvss_boundary_values_are_accepted(score):
    actor, _, organization, _ = setup_context()

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"], cvss_score=score
        ),
    )

    assert response.status_code == 201, response.text


def test_duplicate_vulnerability_reference_is_rejected():
    actor, _, organization, _ = setup_context()
    reference = unique_value("VULN")

    create_vulnerability(
        actor["token"],
        organization["id"],
        vulnerability_ref=reference,
    )

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"], vulnerability_ref=reference
        ),
    )

    assert response.status_code == 409


def test_duplicate_cve_identifier_is_rejected():
    actor, _, organization, _ = setup_context()
    cve_id = "CVE-2024-54321"

    create_vulnerability(
        actor["token"], organization["id"], cve_id=cve_id
    )

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"], cve_id=cve_id
        ),
    )

    assert response.status_code == 409


def test_missing_organization_is_rejected():
    actor, _, _, _ = setup_context()

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(99999999),
    )

    assert response.status_code == 404


def test_missing_asset_is_rejected_on_creation():
    actor, _, organization, _ = setup_context()

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"], asset_ids=[99999999]
        ),
    )

    assert response.status_code == 404


def test_duplicate_asset_ids_are_rejected():
    actor, _, organization, asset = setup_context(with_asset=True)

    response = client.post(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
        json=vulnerability_payload(
            organization["id"],
            asset_ids=[asset["id"], asset["id"]],
        ),
    )

    assert response.status_code == 422


def test_get_vulnerability_success():
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.get(
        f"/api/v1/vulnerabilities/{created['id']}",
        headers=headers(actor["token"]),
    )

    assert response.status_code == 200
    assert response.json()["id"] == created["id"]


def test_missing_vulnerability_returns_404():
    actor, _, _, _ = setup_context()

    response = client.get(
        "/api/v1/vulnerabilities/99999999",
        headers=headers(actor["token"]),
    )

    assert response.status_code == 404


def test_list_vulnerabilities():
    actor, _, organization, _ = setup_context()
    create_vulnerability(actor["token"], organization["id"])
    create_vulnerability(actor["token"], organization["id"])

    response = client.get(
        "/api/v1/vulnerabilities",
        headers=headers(actor["token"]),
    )

    assert response.status_code == 200
    assert len(response.json()) >= 2


def test_filter_vulnerabilities_by_severity():
    actor, _, organization, _ = setup_context()
    create_vulnerability(
        actor["token"], organization["id"], severity="HIGH"
    )
    create_vulnerability(
        actor["token"], organization["id"], severity="LOW",
        cvss_score=2.0,
    )

    response = client.get(
        "/api/v1/vulnerabilities?severity=HIGH",
        headers=headers(actor["token"]),
    )

    assert response.status_code == 200
    assert response.json()
    assert all(item["severity"] == "HIGH" for item in response.json())


def test_update_vulnerability_details():
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.patch(
        f"/api/v1/vulnerabilities/{created['id']}",
        headers=headers(actor["token"]),
        json={
            "title": "Updated OpenSSL vulnerability title",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["title"] == "Updated OpenSSL vulnerability title"
    assert response.json()["severity"] == "CRITICAL"
    assert response.json()["cvss_score"] == 9.8


def test_update_without_fields_is_rejected():
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.patch(
        f"/api/v1/vulnerabilities/{created['id']}",
        headers=headers(actor["token"]),
        json={},
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "new_status",
    [
        "UNDER_REVIEW",
        "IN_REMEDIATION",
        "MITIGATED",
        "ACCEPTED_RISK",
        "CLOSED",
    ],
)
def test_vulnerability_status_can_be_updated(new_status):
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.patch(
        f"/api/v1/vulnerabilities/{created['id']}/status",
        headers=headers(actor["token"]),
        json={
            "status": new_status,
            "details": "Status updated during integration testing",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == new_status


def test_repeating_current_status_is_rejected():
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.patch(
        f"/api/v1/vulnerabilities/{created['id']}/status",
        headers=headers(actor["token"]),
        json={"status": "OPEN"},
    )

    assert response.status_code == 400


def test_invalid_vulnerability_status_is_rejected():
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.patch(
        f"/api/v1/vulnerabilities/{created['id']}/status",
        headers=headers(actor["token"]),
        json={"status": "INVALID_STATUS"},
    )

    assert response.status_code == 422


def test_remediation_deadline_is_saved():
    actor, _, organization, _ = setup_context()
    deadline = (
        datetime.now(timezone.utc) + timedelta(days=7)
    ).isoformat()

    created = create_vulnerability(
        actor["token"],
        organization["id"],
        remediation_deadline=deadline,
    )

    assert created["remediation_deadline"] is not None


def test_link_asset_to_vulnerability():
    actor, _, organization, asset = setup_context(with_asset=True)
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.post(
        f"/api/v1/vulnerabilities/{created['id']}/assets",
        headers=headers(actor["token"]),
        json={"asset_id": asset["id"]},
    )

    assert response.status_code == 201, response.text
    assert response.json()["asset_id"] == asset["id"]


def test_duplicate_asset_link_is_rejected():
    actor, _, organization, asset = setup_context(with_asset=True)
    created = create_vulnerability(actor["token"], organization["id"])

    url = f"/api/v1/vulnerabilities/{created['id']}/assets"
    payload = {"asset_id": asset["id"]}

    first = client.post(url, headers=headers(actor["token"]), json=payload)
    assert first.status_code == 201, first.text

    second = client.post(url, headers=headers(actor["token"]), json=payload)
    assert second.status_code == 409


def test_link_asset_from_another_organization_is_rejected():
    actor, admin, organization, _ = setup_context(with_asset=True)
    other_organization = create_organization(admin["token"])
    other_asset = create_asset(admin["token"], other_organization["id"])
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.post(
        f"/api/v1/vulnerabilities/{created['id']}/assets",
        headers=headers(actor["token"]),
        json={"asset_id": other_asset["id"]},
    )

    assert response.status_code == 400


def test_list_affected_assets():
    actor, _, organization, asset = setup_context(with_asset=True)
    created = create_vulnerability(
        actor["token"],
        organization["id"],
        asset_ids=[asset["id"]],
    )

    response = client.get(
        f"/api/v1/vulnerabilities/{created['id']}/assets",
        headers=headers(actor["token"]),
    )

    assert response.status_code == 200, response.text
    assert any(item["asset_id"] == asset["id"] for item in response.json())


def test_vulnerability_history_records_creation():
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    response = client.get(
        f"/api/v1/vulnerabilities/{created['id']}/history",
        headers=headers(actor["token"]),
    )

    assert response.status_code == 200, response.text
    assert any(item["action"] == "CREATED" for item in response.json())


def test_vulnerability_history_records_status_change():
    actor, _, organization, _ = setup_context()
    created = create_vulnerability(actor["token"], organization["id"])

    client_response = client.patch(
        f"/api/v1/vulnerabilities/{created['id']}/status",
        headers=headers(actor["token"]),
        json={
            "status": "UNDER_REVIEW",
            "details": "Security analyst reviewing the finding",
        },
    )
    assert client_response.status_code == 200, client_response.text

    response = client.get(
        f"/api/v1/vulnerabilities/{created['id']}/history",
        headers=headers(actor["token"]),
    )

    assert response.status_code == 200
    actions = [item["action"] for item in response.json()]
    assert "CREATED" in actions
    assert "STATUS_CHANGED" in actions
