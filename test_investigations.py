import os
from uuid import uuid4

os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://postgres:Srik8499@localhost:5433/"
    "cybersecurity_incident_threat_test"
)
os.environ["ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient
from sqlalchemy import text

from database import Base, SessionLocal, engine
from main import app
from models.user import User


client = TestClient(app)
PASSWORD = "StrongPassword123!"


def cleanup_database():
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE investigations, investigation_notes, "
                "investigation_evidence, investigation_history "
                "RESTART IDENTITY CASCADE"
            )
        )


def setup_module():
    Base.metadata.create_all(bind=engine)
    cleanup_database()


def teardown_module():
    cleanup_database()


def register_user(role="SECURITY_ANALYST"):
    email = f"investigation_{uuid4().hex[:12]}@example.com"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Investigation Test User",
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        db.commit()
        user_id = user.id

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text

    return {"id": user_id, "email": email}, response.json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_alert(token):
    return client.post(
        "/api/v1/alerts",
        headers=headers(token),
        json={
            "source": "EDR",
            "external_alert_id": f"INV-ALERT-{uuid4().hex[:12]}",
            "title": "Suspicious process execution",
            "description": "A process requires investigation",
            "category": "MALWARE",
            "severity": "HIGH",
        },
    )


def create_investigation(token, **overrides):
    alert = create_alert(token)
    assert alert.status_code == 201, alert.text

    payload = {
        "title": "Suspicious process investigation",
        "description": "Investigate the process and collect evidence",
        "priority": "HIGH",
        "alert_id": alert.json()["id"],
    }
    payload.update(overrides)

    response = client.post(
        "/api/v1/investigations",
        headers=headers(token),
        json=payload,
    )
    return response


def test_create_investigation_success():
    _, token = register_user()

    response = create_investigation(token)

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["investigation_number"].startswith("INV-")
    assert data["status"] == "OPEN"
    assert data["priority"] == "HIGH"
    assert data["alert_id"] is not None


def test_investigation_requires_authentication():
    response = client.get("/api/v1/investigations")
    assert response.status_code == 401


def test_viewer_cannot_create_investigation():
    _, analyst_token = register_user("SECURITY_ANALYST")
    _, viewer_token = register_user("VIEWER")

    alert = create_alert(analyst_token)
    assert alert.status_code == 201, alert.text

    response = client.post(
        "/api/v1/investigations",
        headers=headers(viewer_token),
        json={
            "title": "Viewer investigation",
            "description": "Viewer should not create investigations",
            "alert_id": alert.json()["id"],
        },
    )
    assert response.status_code == 403


def test_investigation_requires_related_record():
    _, token = register_user()

    response = client.post(
        "/api/v1/investigations",
        headers=headers(token),
        json={
            "title": "No linked record",
            "description": "This investigation has no linked objects",
        },
    )
    assert response.status_code == 422


def test_add_note_and_timeline():
    _, token = register_user()
    created = create_investigation(token)
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    response = client.post(
        f"/api/v1/investigations/{investigation_id}/notes",
        headers=headers(token),
        json={"note": "Reviewed endpoint telemetry and login records"},
    )
    assert response.status_code == 201, response.text

    timeline = client.get(
        f"/api/v1/investigations/{investigation_id}/timeline",
        headers=headers(token),
    )
    assert timeline.status_code == 200, timeline.text
    actions = [entry["action"] for entry in timeline.json()]
    assert "CREATED" in actions
    assert "NOTE_ADDED" in actions


def test_add_and_read_evidence():
    _, token = register_user()
    created = create_investigation(token)
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    added = client.post(
        f"/api/v1/investigations/{investigation_id}/evidence",
        headers=headers(token),
        json={
            "reference": "vault://case-001/process-log",
            "evidence_type": "LOG",
            "description": "Endpoint process log retained in the evidence vault",
            "is_sensitive": True,
        },
    )
    assert added.status_code == 201, added.text

    response = client.get(
        f"/api/v1/investigations/{investigation_id}/evidence",
        headers=headers(token),
    )
    assert response.status_code == 200, response.text
    assert any(
        item["reference"] == "vault://case-001/process-log"
        for item in response.json()
    )


def test_viewer_cannot_see_sensitive_evidence():
    _, analyst_token = register_user("SECURITY_ANALYST")
    _, viewer_token = register_user("VIEWER")

    created = create_investigation(analyst_token)
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    added = client.post(
        f"/api/v1/investigations/{investigation_id}/evidence",
        headers=headers(analyst_token),
        json={
            "reference": "vault://case-002/sensitive",
            "evidence_type": "DOCUMENT",
            "description": "Sensitive investigation report",
            "is_sensitive": True,
        },
    )
    assert added.status_code == 201, added.text

    response = client.get(
        f"/api/v1/investigations/{investigation_id}/evidence",
        headers=headers(viewer_token),
    )
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_investigation_status_transition():
    _, token = register_user()
    created = create_investigation(token)
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    response = client.patch(
        f"/api/v1/investigations/{investigation_id}",
        headers=headers(token),
        json={"status": "IN_PROGRESS"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "IN_PROGRESS"

    completed = client.patch(
        f"/api/v1/investigations/{investigation_id}",
        headers=headers(token),
        json={"status": "COMPLETED"},
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["completed_at"] is not None


def test_completed_investigation_cannot_be_modified():
    _, token = register_user()
    created = create_investigation(token)
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    in_progress = client.patch(
        f"/api/v1/investigations/{investigation_id}",
        headers=headers(token),
        json={"status": "IN_PROGRESS"},
    )
    assert in_progress.status_code == 200, in_progress.text

    completed = client.patch(
        f"/api/v1/investigations/{investigation_id}",
        headers=headers(token),
        json={"status": "COMPLETED"},
    )
    assert completed.status_code == 200, completed.text

    response = client.patch(
        f"/api/v1/investigations/{investigation_id}",
        headers=headers(token),
        json={"title": "Attempt to edit completed investigation"},
    )
    assert response.status_code == 409