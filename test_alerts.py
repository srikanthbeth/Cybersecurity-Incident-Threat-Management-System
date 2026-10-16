
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
from models.alert import Alert
from models.user import User


client = TestClient(app)
PASSWORD = "StrongPassword123!"


def cleanup_database():
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE security_alerts, security_team_members, "
                "security_teams, assets, organizations, "
                "password_reset_tokens, revoked_tokens, users "
                "RESTART IDENTITY CASCADE"
            )
        )


def setup_module():
    Base.metadata.create_all(bind=engine)
    cleanup_database()


def teardown_module():
    cleanup_database()


def register_user(role="SECURITY_ANALYST", active=True):
    email = f"user_{uuid4().hex[:12]}@example.com"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Alert Test User",
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

    user_data = {"id": user_id, "email": email, "password": PASSWORD}
    if active:
        login = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": PASSWORD},
        )
        assert login.status_code == 200, login.text
        return user_data, login.json()["access_token"]

    return user_data, None


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_alert(token, **overrides):
    payload = {
        "source": "EDR",
        "external_alert_id": f"EXT-{uuid4().hex[:12]}",
        "title": "Suspicious process execution",
        "description": "Unusual process behavior detected",
        "category": "MALWARE",
        "severity": "HIGH",
    }
    payload.update(overrides)

    return client.post(
        "/api/v1/alerts",
        headers=headers(token),
        json=payload,
    )


def test_analyst_can_create_alert():
    _, token = register_user("SECURITY_ANALYST")

    response = create_alert(token)

    assert response.status_code == 201, response.text
    assert response.json()["severity"] == "HIGH"
    assert response.json()["status"] == "NEW"
    assert response.json()["created_by"] is not None


def test_manager_can_create_alert():
    _, token = register_user("SECURITY_MANAGER")

    response = create_alert(token)

    assert response.status_code == 201, response.text


def test_super_admin_can_create_alert():
    _, token = register_user("SUPER_ADMIN")

    response = create_alert(token)

    assert response.status_code == 201, response.text


def test_viewer_cannot_create_alert():
    _, token = register_user("VIEWER")

    response = create_alert(token)

    assert response.status_code == 403


def test_alert_creation_requires_authentication():
    response = client.post(
        "/api/v1/alerts",
        json={
            "source": "EDR",
            "title": "Suspicious process execution",
        },
    )

    assert response.status_code == 401


def test_duplicate_external_alert_is_rejected():
    _, token = register_user("SECURITY_ANALYST")
    external_id = f"DUP-{uuid4().hex[:12]}"

    first = create_alert(token, external_alert_id=external_id)
    assert first.status_code == 201, first.text

    second = create_alert(token, external_alert_id=external_id)
    assert second.status_code == 409


def test_same_external_id_from_different_sources_is_allowed():
    _, token = register_user("SECURITY_ANALYST")
    external_id = f"SOURCE-{uuid4().hex[:8]}"

    first = create_alert(
        token,
        source="EDR",
        external_alert_id=external_id,
    )
    second = create_alert(
        token,
        source="SIEM",
        external_alert_id=external_id,
    )

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text


def test_alert_title_validation():
    _, token = register_user("SECURITY_ANALYST")

    response = create_alert(token, title="ab")

    assert response.status_code == 422


def test_invalid_alert_severity_is_rejected():
    _, token = register_user("SECURITY_ANALYST")

    response = create_alert(token, severity="EXTREME")

    assert response.status_code == 422


def test_invalid_alert_category_is_rejected():
    _, token = register_user("SECURITY_ANALYST")

    response = create_alert(token, category="UNKNOWN_CATEGORY")

    assert response.status_code == 422


def test_list_alerts():
    _, token = register_user("SECURITY_ANALYST")
    created = create_alert(token)
    assert created.status_code == 201, created.text

    response = client.get("/api/v1/alerts", headers=headers(token))

    assert response.status_code == 200, response.text
    assert any(item["id"] == created.json()["id"] for item in response.json())


def test_list_alerts_requires_authentication():
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401


def test_filter_alerts_by_severity():
    _, token = register_user("SECURITY_ANALYST")
    low = create_alert(token, severity="LOW")
    high = create_alert(token, severity="HIGH")
    assert low.status_code == 201, low.text
    assert high.status_code == 201, high.text

    response = client.get(
        "/api/v1/alerts",
        params={"severity": "HIGH"},
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert all(item["severity"] == "HIGH" for item in response.json())


def test_filter_alerts_by_status():
    _, token = register_user("SECURITY_ANALYST")
    created = create_alert(token)
    assert created.status_code == 201, created.text

    update = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(token),
        json={"status": "ACKNOWLEDGED"},
    )
    assert update.status_code == 200, update.text

    response = client.get(
        "/api/v1/alerts",
        params={"status": "ACKNOWLEDGED"},
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert all(item["status"] == "ACKNOWLEDGED" for item in response.json())


def test_search_alerts_by_title():
    _, token = register_user("SECURITY_ANALYST")
    title = f"Searchable alert {uuid4().hex[:8]}"
    created = create_alert(token, title=title)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/alerts",
        params={"search": title},
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert any(item["title"] == title for item in response.json())


def test_alert_pagination():
    _, token = register_user("SECURITY_ANALYST")
    for _ in range(3):
        response = create_alert(token)
        assert response.status_code == 201, response.text

    response = client.get(
        "/api/v1/alerts",
        params={"page": 1, "page_size": 2},
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert len(response.json()) <= 2


def test_get_alert_by_id():
    _, token = register_user("SECURITY_ANALYST")
    created = create_alert(token)
    assert created.status_code == 201, created.text

    response = client.get(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == created.json()["id"]


def test_missing_alert_returns_404():
    _, token = register_user("SECURITY_ANALYST")

    response = client.get(
        "/api/v1/alerts/999999",
        headers=headers(token),
    )

    assert response.status_code == 404


def test_analyst_can_update_alert_severity():
    _, token = register_user("SECURITY_ANALYST")
    created = create_alert(token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(token),
        json={"severity": "CRITICAL"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["severity"] == "CRITICAL"


def test_alert_status_can_be_acknowledged():
    _, token = register_user("SECURITY_ANALYST")
    created = create_alert(token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(token),
        json={"status": "ACKNOWLEDGED"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "ACKNOWLEDGED"


def test_alert_can_move_to_investigating():
    _, analyst_token = register_user("SECURITY_ANALYST")
    _, responder_token = register_user("INCIDENT_RESPONDER")

    created = create_alert(
        analyst_token,
        external_alert_id=f"RESP-{uuid4().hex[:8]}",
    )
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(responder_token),
        json={"status": "INVESTIGATING"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "INVESTIGATING"


def test_invalid_alert_status_transition_is_rejected():
    _, token = register_user("SECURITY_ANALYST")
    created = create_alert(token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(token),
        json={"status": "RESOLVED"},
    )

    assert response.status_code == 409


def test_viewer_cannot_update_alert():
    _, admin_token = register_user("SUPER_ADMIN")
    created = create_alert(admin_token)
    assert created.status_code == 201, created.text

    _, viewer_token = register_user("VIEWER")
    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(viewer_token),
        json={"severity": "LOW"},
    )

    assert response.status_code == 403


def test_assign_alert_to_analyst():
    _, manager_token = register_user("SECURITY_MANAGER")
    analyst, _ = register_user("SECURITY_ANALYST")
    created = create_alert(manager_token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(manager_token),
        json={"assigned_to": analyst["id"]},
    )

    assert response.status_code == 200, response.text
    assert response.json()["assigned_to"] == analyst["id"]


def test_cannot_assign_alert_to_viewer():
    _, manager_token = register_user("SECURITY_MANAGER")
    viewer, _ = register_user("VIEWER")
    created = create_alert(manager_token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(manager_token),
        json={"assigned_to": viewer["id"]},
    )

    assert response.status_code == 422


def test_assign_alert_to_missing_user_returns_404():
    _, manager_token = register_user("SECURITY_MANAGER")
    created = create_alert(manager_token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/alerts/{created.json()['id']}",
        headers=headers(manager_token),
        json={"assigned_to": 999999},
    )

    assert response.status_code == 404
