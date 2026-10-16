
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
                "TRUNCATE TABLE "
                "correlation_history, "
                "incident_relationships, "
                "alert_correlation_members, "
                "alert_correlation_groups, "
                "incident_notes, "
                "incident_history, "
                "incident_alerts, "
                "incidents, "
                "security_alerts, "
                "security_team_members, "
                "security_teams, "
                "assets, "
                "organizations, "
                "password_reset_tokens, "
                "revoked_tokens, "
                "users "
                "RESTART IDENTITY CASCADE"
            )
        )


def setup_module():
    Base.metadata.create_all(bind=engine)
    cleanup_database()


def teardown_module():
    cleanup_database()


def register_user(role="SECURITY_ANALYST", active=True):
    email = f"correlation_{uuid4().hex[:12]}@example.com"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Correlation Test User",
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
        json={
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 200, response.text

    return user_data, response.json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_alert(token, **overrides):
    payload = {
        "source": "EDR",
        "external_alert_id": f"CORR-{uuid4().hex[:12]}",
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
        "title": f"Correlation incident {uuid4().hex[:8]}",
        "description": "Investigation of correlated security alerts",
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


def create_group(token, **overrides):
    payload = {
        "name": f"Correlation Group {uuid4().hex[:8]}",
        "description": "Group related security alerts",
        "rule_type": "MANUAL",
    }
    payload.update(overrides)

    return client.post(
        "/api/v1/correlation/groups",
        headers=headers(token),
        json=payload,
    )


def test_create_correlation_group():
    _, token = register_user()

    response = create_group(token)

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["name"].startswith("Correlation Group")
    assert data["rule_type"] == "MANUAL"
    assert data["status"] == "ACTIVE"
    assert data["created_by"] is not None


def test_manager_can_create_correlation_group():
    _, token = register_user("SECURITY_MANAGER")

    response = create_group(token)

    assert response.status_code == 201, response.text


def test_super_admin_can_create_correlation_group():
    _, token = register_user("SUPER_ADMIN")

    response = create_group(token)

    assert response.status_code == 201, response.text


def test_viewer_cannot_create_correlation_group():
    _, token = register_user("VIEWER")

    response = create_group(token)

    assert response.status_code == 403


def test_create_correlation_group_requires_authentication():
    response = client.post(
        "/api/v1/correlation/groups",
        json={
            "name": "Unauthenticated Group",
            "rule_type": "MANUAL",
        },
    )

    assert response.status_code == 401


def test_correlation_group_name_validation():
    _, token = register_user()

    response = create_group(token, name="ab")

    assert response.status_code == 422


def test_invalid_correlation_rule_is_rejected():
    _, token = register_user()

    response = create_group(token, rule_type="INVALID_RULE")

    assert response.status_code == 422


def test_list_correlation_groups():
    _, token = register_user()

    created = create_group(token)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/correlation/groups",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert any(
        group["id"] == created.json()["id"]
        for group in response.json()
    )


def test_list_correlation_groups_requires_authentication():
    response = client.get("/api/v1/correlation/groups")

    assert response.status_code == 401


def test_add_alert_to_correlation_group():
    _, token = register_user()

    group_response = create_group(token)
    assert group_response.status_code == 201, group_response.text

    alert_response = create_alert(token)
    assert alert_response.status_code == 201, alert_response.text

    group_id = group_response.json()["id"]
    alert_id = alert_response.json()["id"]

    response = client.post(
        f"/api/v1/correlation/groups/{group_id}/alerts",
        headers=headers(token),
        json={"alert_id": alert_id},
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["group_id"] == group_id
    assert data["alert_id"] == alert_id
    assert data["added_by"] is not None


def test_missing_correlation_group_returns_404():
    _, token = register_user()

    alert_response = create_alert(token)
    assert alert_response.status_code == 201, alert_response.text

    response = client.post(
        "/api/v1/correlation/groups/999999/alerts",
        headers=headers(token),
        json={"alert_id": alert_response.json()["id"]},
    )

    assert response.status_code == 404


def test_missing_alert_returns_404_when_adding_to_group():
    _, token = register_user()

    group_response = create_group(token)
    assert group_response.status_code == 201, group_response.text

    response = client.post(
        f"/api/v1/correlation/groups/{group_response.json()['id']}/alerts",
        headers=headers(token),
        json={"alert_id": 999999},
    )

    assert response.status_code == 404


def test_duplicate_alert_in_same_group_is_rejected():
    _, token = register_user()

    group_response = create_group(token)
    assert group_response.status_code == 201, group_response.text

    alert_response = create_alert(token)
    assert alert_response.status_code == 201, alert_response.text

    group_id = group_response.json()["id"]
    alert_id = alert_response.json()["id"]

    first = client.post(
        f"/api/v1/correlation/groups/{group_id}/alerts",
        headers=headers(token),
        json={"alert_id": alert_id},
    )
    assert first.status_code == 201, first.text

    second = client.post(
        f"/api/v1/correlation/groups/{group_id}/alerts",
        headers=headers(token),
        json={"alert_id": alert_id},
    )

    assert second.status_code == 409


def test_list_alerts_in_correlation_group():
    _, token = register_user()

    group_response = create_group(token)
    assert group_response.status_code == 201, group_response.text

    alert_response = create_alert(token)
    assert alert_response.status_code == 201, alert_response.text

    group_id = group_response.json()["id"]
    alert_id = alert_response.json()["id"]

    added = client.post(
        f"/api/v1/correlation/groups/{group_id}/alerts",
        headers=headers(token),
        json={"alert_id": alert_id},
    )
    assert added.status_code == 201, added.text

    response = client.get(
        f"/api/v1/correlation/groups/{group_id}/alerts",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    assert any(item["alert_id"] == alert_id for item in response.json())


def test_correlate_alert_without_asset():
    _, token = register_user()

    alert_response = create_alert(token)
    assert alert_response.status_code == 201, alert_response.text

    alert_id = alert_response.json()["id"]

    response = client.get(
        f"/api/v1/correlation/alerts/{alert_id}/related",
        headers=headers(token),
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["asset_id"] is None
    assert data["matching_alert_ids"] == []
    assert data["window_minutes"] == 60


def test_correlate_missing_alert_returns_404():
    _, token = register_user()

    response = client.get(
        "/api/v1/correlation/alerts/999999/related",
        headers=headers(token),
    )

    assert response.status_code == 404


def test_correlation_rejects_zero_minute_window():
    _, token = register_user()

    response = client.get(
        "/api/v1/correlation/alerts/1/related",
        params={"window_minutes": 0},
        headers=headers(token),
    )

    assert response.status_code == 422


def test_correlation_rejects_excessive_time_window():
    _, token = register_user()

    response = client.get(
        "/api/v1/correlation/alerts/1/related",
        params={"window_minutes": 10081},
        headers=headers(token),
    )

    assert response.status_code == 422


def test_create_incident_relationship_rejects_self_relationship():
    _, token = register_user()

    response = client.post(
        "/api/v1/correlation/incidents/1/related",
        headers=headers(token),
        json={
            "target_incident_id": 1,
            "relationship_type": "RELATED",
            "details": "Self-relationships must be rejected",
        },
    )

    assert response.status_code == 400


def test_incident_relationship_requires_authentication():
    response = client.post(
        "/api/v1/correlation/incidents/1/related",
        json={
            "target_incident_id": 2,
            "relationship_type": "RELATED",
        },
    )

    assert response.status_code == 401


def test_correlation_history_requires_authentication():
    response = client.get("/api/v1/correlation/history")

    assert response.status_code == 401


def test_correlation_history_records_group_creation():
    _, token = register_user()

    group_response = create_group(token)
    assert group_response.status_code == 201, group_response.text

    group_id = group_response.json()["id"]

    response = client.get(
        "/api/v1/correlation/history",
        headers=headers(token),
        params={
            "entity_type": "GROUP",
            "entity_id": group_id,
        },
    )

    assert response.status_code == 200, response.text
    assert any(
        item["action"] == "GROUP_CREATED"
        and item["entity_id"] == group_id
        for item in response.json()
    )
