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
                "TRUNCATE TABLE incidents, security_alerts, "
                "security_team_members, security_teams, assets, "
                "organizations, password_reset_tokens, revoked_tokens, users "
                "RESTART IDENTITY CASCADE"
            )
        )


def setup_module():
    Base.metadata.create_all(bind=engine)
    cleanup_database()


def teardown_module():
    cleanup_database()


def register_user(role="SECURITY_ANALYST", active=True):
    email = f"incident_{uuid4().hex[:12]}@example.com"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Incident Test User",
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 201, response.text

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        user.is_active = active
        db.commit()
        user_id = user.id

    user_data = {
        "id": user_id,
        "email": email,
        "password": PASSWORD,
    }

    if not active:
        return user_data, None

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text

    return user_data, response.json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_alert(token, **overrides):
    payload = {
        "source": "EDR",
        "external_alert_id": f"INC-ALERT-{uuid4().hex[:12]}",
        "title": "Suspicious login activity",
        "description": "Repeated unauthorized login attempts detected",
        "category": "UNAUTHORIZED_ACCESS",
        "severity": "HIGH",
    }
    payload.update(overrides)

    return client.post(
        "/api/v1/alerts",
        headers=headers(token),
        json=payload,
    )


def create_incident(token, **overrides):
    alert_response = create_alert(token)
    assert alert_response.status_code == 201, alert_response.text

    payload = {
        "alert_id": alert_response.json()["id"],
        "title": f"Security incident {uuid4().hex[:8]}",
        "description": "Investigation of suspicious security activity",
        "category": "UNAUTHORIZED_ACCESS",
        "severity": "HIGH",
        "assigned_to": None,
    }
    payload.update(overrides)

    response = client.post(
        "/api/v1/incidents",
        headers=headers(token),
        json=payload,
    )
    return response, alert_response.json()


def test_create_incident_success():
    _, token = register_user()

    response, alert = create_incident(token)

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["title"].startswith("Security incident")
    assert data["status"] == "NEW"
    assert data["created_by"] is not None
    assert data["incident_number"].startswith("INC-")
    assert data["severity"] == "HIGH"


def test_manager_can_create_incident():
    _, token = register_user("SECURITY_MANAGER")

    response, _ = create_incident(token)

    assert response.status_code == 201, response.text


def test_super_admin_can_create_incident():
    _, token = register_user("SUPER_ADMIN")

    response, _ = create_incident(token)

    assert response.status_code == 201, response.text


def test_viewer_cannot_create_incident():
    _, analyst_token = register_user("SECURITY_ANALYST")
    _, viewer_token = register_user("VIEWER")

    alert_response = create_alert(analyst_token)
    assert alert_response.status_code == 201, alert_response.text

    response = client.post(
        "/api/v1/incidents",
        headers=headers(viewer_token),
        json={
            "alert_id": alert_response.json()["id"],
            "title": "Unauthorized incident creation",
            "description": "Verify that viewers cannot create incidents",
            "category": "UNAUTHORIZED_ACCESS",
            "severity": "HIGH",
        },
    )

    assert response.status_code == 403


def test_create_incident_requires_authentication():
    response = client.post(
        "/api/v1/incidents",
        json={
            "alert_id": 1,
            "title": "Suspicious login activity",
            "description": "Unauthorized login attempts detected",
            "category": "UNAUTHORIZED_ACCESS",
            "severity": "HIGH",
        },
    )

    assert response.status_code == 401


def test_missing_alert_returns_404():
    _, token = register_user()

    response = client.post(
        "/api/v1/incidents",
        headers=headers(token),
        json={
            "alert_id": 999999,
            "title": "Missing alert incident",
            "description": "This alert does not exist",
            "category": "OTHER",
            "severity": "LOW",
        },
    )

    assert response.status_code == 404


def test_duplicate_alert_incident_is_rejected():
    _, token = register_user()

    first, alert = create_incident(token)
    assert first.status_code == 201, first.text

    second = client.post(
        "/api/v1/incidents",
        headers=headers(token),
        json={
            "alert_id": alert["id"],
            "title": "Duplicate incident",
            "description": "Attempt to reuse the same alert",
            "category": "OTHER",
            "severity": "MEDIUM",
        },
    )

    assert second.status_code == 409


def test_incident_title_validation():
    _, token = register_user()

    response, _ = create_incident(token, title="ab")

    assert response.status_code == 422


def test_incident_description_validation():
    _, token = register_user()

    response, _ = create_incident(token, description="bad")

    assert response.status_code == 422


def test_invalid_incident_severity_is_rejected():
    _, token = register_user()

    response, _ = create_incident(token, severity="EXTREME")

    assert response.status_code == 422


def test_invalid_incident_category_is_rejected():
    _, token = register_user()

    response, _ = create_incident(token, category="UNKNOWN")

    assert response.status_code == 422


def test_create_incident_with_assignment():
    _, token = register_user("SECURITY_MANAGER")
    analyst, _ = register_user("SECURITY_ANALYST")

    response, _ = create_incident(
        token,
        assigned_to=analyst["id"],
    )

    assert response.status_code == 201, response.text
    assert response.json()["assigned_to"] == analyst["id"]
    assert response.json()["status"] == "ASSIGNED"


def test_cannot_assign_incident_to_viewer():
    _, token = register_user("SECURITY_MANAGER")
    viewer, _ = register_user("VIEWER")

    response, _ = create_incident(
        token,
        assigned_to=viewer["id"],
    )

    assert response.status_code == 400


def test_cannot_assign_incident_to_missing_user():
    _, token = register_user("SECURITY_MANAGER")

    response, _ = create_incident(
        token,
        assigned_to=999999,
    )

    assert response.status_code == 400


def test_list_incidents():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/incidents",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert "items" in response.json()
    assert "total" in response.json()
    assert any(
        item["id"] == created.json()["id"]
        for item in response.json()["items"]
    )


def test_list_incidents_requires_authentication():
    response = client.get("/api/v1/incidents")

    assert response.status_code == 401


def test_filter_incidents_by_severity():
    _, token = register_user()

    low, _ = create_incident(token, severity="LOW")
    high, _ = create_incident(token, severity="HIGH")

    assert low.status_code == 201, low.text
    assert high.status_code == 201, high.text

    response = client.get(
        "/api/v1/incidents",
        params={"severity": "HIGH"},
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert all(
        item["severity"] == "HIGH"
        for item in response.json()["items"]
    )


def test_filter_incidents_by_status():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/incidents",
        params={"status": "NEW"},
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert all(
        item["status"] == "NEW"
        for item in response.json()["items"]
    )


def test_search_incidents_by_title():
    _, token = register_user()
    title = f"Search incident {uuid4().hex[:8]}"

    created, _ = create_incident(token, title=title)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/incidents",
        params={"search": title},
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert any(
        item["title"] == title
        for item in response.json()["items"]
    )


def test_get_incident_by_id():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]
    response = client.get(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == incident_id


def test_missing_incident_returns_404():
    _, token = register_user()

    response = client.get(
        "/api/v1/incidents/999999",
        headers=headers(token),
    )

    assert response.status_code == 404


def test_transition_new_to_investigating():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/incidents/{created.json()['id']}",
        headers=headers(token),
        json={"status": "INVESTIGATING"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "INVESTIGATING"


def test_invalid_status_transition_is_rejected():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/incidents/{created.json()['id']}",
        headers=headers(token),
        json={"status": "CLOSED"},
    )

    assert response.status_code == 400


def test_resolution_requires_details():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    investigating = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(token),
        json={"status": "INVESTIGATING"},
    )
    assert investigating.status_code == 200, investigating.text

    response = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(token),
        json={"status": "RESOLVED"},
    )

    assert response.status_code == 400


def test_incident_can_be_resolved_with_details():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    investigating = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(token),
        json={"status": "INVESTIGATING"},
    )
    assert investigating.status_code == 200, investigating.text

    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(token),
        json={
            "status": "RESOLVED",
            "resolution_details": "Malicious login blocked and credentials reset",
        },
    )

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "RESOLVED"
    assert resolved.json()["resolution_details"]


def test_add_investigation_note():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]
    response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=headers(token),
        json={"note": "Reviewed authentication logs"},
    )

    assert response.status_code == 201, response.text
    assert response.json()["incident_id"] == incident_id
    assert response.json()["note"] == "Reviewed authentication logs"


def test_investigation_note_validation():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    response = client.post(
        f"/api/v1/incidents/{created.json()['id']}/notes",
        headers=headers(token),
        json={"note": "x"},
    )

    assert response.status_code == 422


def test_get_investigation_notes():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]
    added = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=headers(token),
        json={"note": "Reviewed firewall logs"},
    )
    assert added.status_code == 201, added.text

    response = client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert any(item["note"] == "Reviewed firewall logs" for item in response.json())


def test_incident_history_records_creation_and_notes():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    note = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=headers(token),
        json={"note": "Initial investigation started"},
    )
    assert note.status_code == 201, note.text

    response = client.get(
        f"/api/v1/incidents/{incident_id}/history",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    actions = [item["action"] for item in response.json()]
    assert "CREATED" in actions
    assert "NOTE_ADDED" in actions


def test_request_closure_requires_resolved_status():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    response = client.post(
        f"/api/v1/incidents/{created.json()['id']}/request-closure",
        headers=headers(token),
        json={"details": "Please review for closure"},
    )

    assert response.status_code == 400


def test_closure_approval_requires_closure_request():
    _, token = register_user()
    created, _ = create_incident(token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    investigating = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(token),
        json={"status": "INVESTIGATING"},
    )
    assert investigating.status_code == 200, investigating.text

    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(token),
        json={
            "status": "RESOLVED",
            "resolution_details": "Threat contained and credentials reset",
        },
    )
    assert resolved.status_code == 200, resolved.text

    _, manager_token = register_user("SECURITY_MANAGER")

    response = client.post(
        f"/api/v1/incidents/{incident_id}/approve-closure",
        headers=headers(manager_token),
    )

    assert response.status_code == 400


def test_closure_request_and_approval():
    _, analyst_token = register_user("SECURITY_ANALYST")
    created, _ = create_incident(analyst_token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    investigating = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={"status": "INVESTIGATING"},
    )
    assert investigating.status_code == 200, investigating.text

    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={
            "status": "RESOLVED",
            "resolution_details": "Threat removed and access credentials reset",
        },
    )
    assert resolved.status_code == 200, resolved.text

    request = client.post(
        f"/api/v1/incidents/{incident_id}/request-closure",
        headers=headers(analyst_token),
        json={"details": "Investigation complete; ready for review"},
    )
    assert request.status_code == 200, request.text
    assert request.json()["closure_requested_at"] is not None

    _, manager_token = register_user("SECURITY_MANAGER")

    approval = client.post(
        f"/api/v1/incidents/{incident_id}/approve-closure",
        headers=headers(manager_token),
    )

    assert approval.status_code == 200, approval.text
    assert approval.json()["status"] == "CLOSED"
    assert approval.json()["closure_approved_at"] is not None


def test_viewer_cannot_approve_closure():
    _, analyst_token = register_user("SECURITY_ANALYST")
    created, _ = create_incident(analyst_token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    investigating = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={"status": "INVESTIGATING"},
    )
    assert investigating.status_code == 200, investigating.text

    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={
            "status": "RESOLVED",
            "resolution_details": "Threat removed and access credentials reset",
        },
    )
    assert resolved.status_code == 200, resolved.text

    requested = client.post(
        f"/api/v1/incidents/{incident_id}/request-closure",
        headers=headers(analyst_token),
        json={"details": "Requesting independent approval"},
    )
    assert requested.status_code == 200, requested.text

    _, viewer_token = register_user("VIEWER")

    response = client.post(
        f"/api/v1/incidents/{incident_id}/approve-closure",
        headers=headers(viewer_token),
    )

    assert response.status_code == 403


def test_closed_incident_cannot_be_modified():
    _, analyst_token = register_user("SECURITY_ANALYST")
    created, _ = create_incident(analyst_token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    investigating = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={"status": "INVESTIGATING"},
    )
    assert investigating.status_code == 200, investigating.text

    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={
            "status": "RESOLVED",
            "resolution_details": "Threat removed and access credentials reset",
        },
    )
    assert resolved.status_code == 200, resolved.text

    requested = client.post(
        f"/api/v1/incidents/{incident_id}/request-closure",
        headers=headers(analyst_token),
        json={"details": "Ready for final approval"},
    )
    assert requested.status_code == 200, requested.text

    _, manager_token = register_user("SECURITY_MANAGER")

    approved = client.post(
        f"/api/v1/incidents/{incident_id}/approve-closure",
        headers=headers(manager_token),
    )
    assert approved.status_code == 200, approved.text

    update = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={"title": "Modified closed incident"},
    )

    assert update.status_code == 409


def test_closed_incident_cannot_receive_notes():
    _, analyst_token = register_user("SECURITY_ANALYST")
    created, _ = create_incident(analyst_token)
    assert created.status_code == 201, created.text

    incident_id = created.json()["id"]

    investigating = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={"status": "INVESTIGATING"},
    )
    assert investigating.status_code == 200, investigating.text

    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers(analyst_token),
        json={
            "status": "RESOLVED",
            "resolution_details": "Threat removed and access credentials reset",
        },
    )
    assert resolved.status_code == 200, resolved.text

    requested = client.post(
        f"/api/v1/incidents/{incident_id}/request-closure",
        headers=headers(analyst_token),
        json={"details": "Ready for approval"},
    )
    assert requested.status_code == 200, requested.text

    _, manager_token = register_user("SECURITY_MANAGER")

    approved = client.post(
        f"/api/v1/incidents/{incident_id}/approve-closure",
        headers=headers(manager_token),
    )
    assert approved.status_code == 200, approved.text

    response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=headers(analyst_token),
        json={"note": "Attempt to modify closed incident"},
    )

    assert response.status_code == 409
