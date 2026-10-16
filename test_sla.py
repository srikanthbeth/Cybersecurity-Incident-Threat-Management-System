
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from database import SessionLocal
from main import app
from models.incident import Incident
from models.user import User
from models.incident_sla import IncidentSLA
from models.sla_policy import SLAPolicy

client = TestClient(app)

@pytest.fixture(autouse=True)
def cleanup_sla_records():
    db = SessionLocal()
    try:
        db.query(IncidentSLA).delete()
        db.query(SLAPolicy).delete()
        db.commit()
    finally:
        db.close()

    yield

    db = SessionLocal()
    try:
        db.query(IncidentSLA).delete()
        db.query(SLAPolicy).delete()
        db.commit()
    finally:
        db.close()

BASE_URL = "/api/v1/sla"


def create_user_and_token(role="SUPER_ADMIN"):
    email = f"sla_{uuid4().hex[:10]}@example.com"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "SLA Integration Tester",
            "email": email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code in (200, 201), response.text

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        db.commit()
        user_id = user.id
    finally:
        db.close()

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 200, response.text

    token = response.json().get("access_token")
    assert token

    return {"Authorization": f"Bearer {token}"}, user_id


def create_policy(headers, severity="HIGH"):
    response = client.post(
        f"{BASE_URL}/policies",
        headers=headers,
        json={
            "severity": severity,
            "acknowledgment_minutes": 30,
            "investigation_minutes": 120,
            "resolution_minutes": 480,
            "escalation_after_minutes": 15,
            "is_active": True,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_incident(user_id, severity="HIGH"):
    db = SessionLocal()
    try:
        incident = Incident(
            incident_number=f"SLA-{uuid4().hex[:12].upper()}",
            title="SLA integration test incident",
            description="Incident created for SLA integration testing",
            category="MALWARE",
            severity=severity,
            status="NEW",
            created_by=user_id,
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        incident_id = incident.id
    finally:
        db.close()

    return incident_id


@pytest.fixture
def admin():
    return create_user_and_token("SUPER_ADMIN")


@pytest.fixture
def analyst():
    return create_user_and_token("SECURITY_ANALYST")


def test_sla_policies_require_authentication():
    response = client.get(f"{BASE_URL}/policies")
    assert response.status_code == 401


def test_admin_can_create_and_list_sla_policy(admin):
    headers, _ = admin
    policy = create_policy(headers, "HIGH")

    assert policy["severity"] == "HIGH"
    assert policy["acknowledgment_minutes"] == 30
    assert policy["investigation_minutes"] == 120
    assert policy["resolution_minutes"] == 480
    assert policy["is_active"] is True

    response = client.get(f"{BASE_URL}/policies", headers=headers)
    assert response.status_code == 200
    assert any(item["id"] == policy["id"] for item in response.json())


def test_duplicate_sla_policy_is_rejected(admin):
    headers, _ = admin
    create_policy(headers, "CRITICAL")

    response = client.post(
        f"{BASE_URL}/policies",
        headers=headers,
        json={
            "severity": "CRITICAL",
            "acknowledgment_minutes": 10,
            "investigation_minutes": 20,
            "resolution_minutes": 60,
            "escalation_after_minutes": 10,
            "is_active": True,
        },
    )

    assert response.status_code == 409


def test_analyst_cannot_create_sla_policy(analyst):
    headers, _ = analyst

    response = client.post(
        f"{BASE_URL}/policies",
        headers=headers,
        json={
            "severity": "LOW",
            "acknowledgment_minutes": 480,
            "investigation_minutes": 1440,
            "resolution_minutes": 2880,
            "escalation_after_minutes": 60,
            "is_active": True,
        },
    )

    assert response.status_code == 403


def test_invalid_sla_policy_values_are_rejected(admin):
    headers, _ = admin

    response = client.post(
        f"{BASE_URL}/policies",
        headers=headers,
        json={
            "severity": "HIGH",
            "acknowledgment_minutes": 0,
            "investigation_minutes": 120,
            "resolution_minutes": 480,
            "escalation_after_minutes": 15,
            "is_active": True,
        },
    )

    assert response.status_code == 422


def test_admin_can_update_sla_policy(admin):
    headers, _ = admin
    policy = create_policy(headers, "MEDIUM")

    response = client.patch(
        f"{BASE_URL}/policies/{policy['id']}",
        headers=headers,
        json={"acknowledgment_minutes": 90},
    )

    assert response.status_code == 200, response.text
    assert response.json()["acknowledgment_minutes"] == 90


def test_start_incident_sla_creates_deadlines(admin):
    headers, user_id = admin
    create_policy(headers, "HIGH")
    incident_id = create_incident(user_id, "HIGH")

    response = client.post(
        f"{BASE_URL}/incidents/{incident_id}",
        headers=headers,
    )

    assert response.status_code == 201, response.text
    data = response.json()

    assert data["incident_id"] == incident_id
    assert data["severity"] == "HIGH"

    started_at = datetime.fromisoformat(data["started_at"])
    ack_deadline = datetime.fromisoformat(data["acknowledgment_deadline"])
    investigation_deadline = datetime.fromisoformat(
        data["investigation_deadline"]
    )
    resolution_deadline = datetime.fromisoformat(
        data["resolution_deadline"]
    )

    assert ack_deadline - started_at == timedelta(minutes=30)
    assert investigation_deadline - started_at == timedelta(minutes=120)
    assert resolution_deadline - started_at == timedelta(minutes=480)


def test_starting_incident_sla_twice_does_not_duplicate(admin):
    headers, user_id = admin
    create_policy(headers, "HIGH")
    incident_id = create_incident(user_id, "HIGH")

    first = client.post(
        f"{BASE_URL}/incidents/{incident_id}",
        headers=headers,
    )
    second = client.post(
        f"{BASE_URL}/incidents/{incident_id}",
        headers=headers,
    )

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["id"] == second.json()["id"]


def test_missing_incident_returns_404(admin):
    headers, _ = admin
    create_policy(headers, "HIGH")

    response = client.post(
        f"{BASE_URL}/incidents/99999999",
        headers=headers,
    )

    assert response.status_code == 404


def test_acknowledgment_event_records_actual_response_time(admin):
    headers, user_id = admin
    create_policy(headers, "HIGH")
    incident_id = create_incident(user_id, "HIGH")

    start = client.post(
        f"{BASE_URL}/incidents/{incident_id}",
        headers=headers,
    )
    assert start.status_code == 201, start.text

    event = client.post(
        f"{BASE_URL}/incidents/{incident_id}/events",
        headers=headers,
        json={"event": "ACKNOWLEDGED"},
    )

    assert event.status_code == 200, event.text
    data = event.json()
    assert data["acknowledged_at"] is not None
    assert data["actual_response_minutes"] is not None
    assert data["actual_response_minutes"] >= 0


def test_duplicate_acknowledgment_event_is_rejected(admin):
    headers, user_id = admin
    create_policy(headers, "HIGH")
    incident_id = create_incident(user_id, "HIGH")

    client.post(f"{BASE_URL}/incidents/{incident_id}", headers=headers)

    first = client.post(
        f"{BASE_URL}/incidents/{incident_id}/events",
        headers=headers,
        json={"event": "ACKNOWLEDGED"},
    )
    second = client.post(
        f"{BASE_URL}/incidents/{incident_id}/events",
        headers=headers,
        json={"event": "ACKNOWLEDGED"},
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 409


def test_approaching_deadlines_endpoint_returns_list(admin):
    headers, _ = admin

    response = client.get(
        f"{BASE_URL}/approaching?within_minutes=30",
        headers=headers,
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_breached_deadlines_endpoint_returns_list(admin):
    headers, _ = admin

    response = client.get(
        f"{BASE_URL}/breached",
        headers=headers,
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_sla_summary_has_expected_fields(admin):
    headers, _ = admin

    response = client.get(f"{BASE_URL}/summary", headers=headers)

    assert response.status_code == 200, response.text
    data = response.json()

    assert data["total_tracked"] >= 0
    assert "on_track" in data
    assert "approaching_deadline" in data
    assert "breached" in data
    assert "resolved" in data
    assert "escalation_pending" in data
    assert "escalated" in data


def test_viewer_cannot_start_incident_sla():
    admin_headers, _ = create_user_and_token("SUPER_ADMIN")
    viewer_headers, viewer_id = create_user_and_token("VIEWER")

    create_policy(admin_headers, "HIGH")
    incident_id = create_incident(viewer_id, "HIGH")

    response = client.post(
        f"{BASE_URL}/incidents/{incident_id}",
        headers=viewer_headers,
    )

    assert response.status_code == 403

def test_event_payload_rejects_unknown_event(admin):
    headers, user_id = admin
    create_policy(headers, "HIGH")
    incident_id = create_incident(user_id, "HIGH")

    response = client.post(
        f"{BASE_URL}/incidents/{incident_id}/events",
        headers=headers,
        json={"event": "UNKNOWN_EVENT"},
    )

    assert response.status_code == 422
