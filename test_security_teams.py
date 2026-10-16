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

client = TestClient(app)
PASSWORD = "TestPassword123!"


def unique_email():
    return f"team_{uuid.uuid4().hex[:12]}@example.com"


def register_and_login(role="SUPER_ADMIN", active=True):
    email = unique_email()

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Security Team Tester",
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code in (200, 201), response.text

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        user.is_active = active
        db.commit()
        user_id = user.id

    if not active:
        return {"id": user_id, "email": email}, None

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text

    token = response.json()["access_token"]
    return (
        {"id": user_id, "email": email},
        {"Authorization": f"Bearer {token}"},
    )


def create_team(headers, **overrides):
    code = f"TEAM-{uuid.uuid4().hex[:8].upper()}"
    payload = {
        "name": f"Security Team {code}",
        "code": code,
        "description": "Integration test security team",
    }
    payload.update(overrides)

    return client.post(
        "/api/v1/security-teams",
        headers=headers,
        json=payload,
    )


def test_create_security_team_success():
    _, headers = register_and_login("SUPER_ADMIN")

    response = create_team(headers)

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["id"] is not None
    assert data["name"].startswith("Security Team")
    assert data["code"].startswith("TEAM-")
    assert data["is_active"] is True


def test_security_manager_can_create_team():
    _, headers = register_and_login("SECURITY_MANAGER")

    response = create_team(headers)

    assert response.status_code == 201, response.text


def test_analyst_cannot_create_team():
    _, headers = register_and_login("SECURITY_ANALYST")

    response = create_team(headers)

    assert response.status_code == 403


def test_viewer_cannot_create_team():
    _, headers = register_and_login("VIEWER")

    response = create_team(headers)

    assert response.status_code == 403


def test_create_team_requires_authentication():
    response = create_team(None)

    assert response.status_code in (401, 403)


def test_duplicate_team_code_is_rejected():
    _, headers = register_and_login("SUPER_ADMIN")
    code = f"DUP-{uuid.uuid4().hex[:8].upper()}"

    first = create_team(headers, code=code)
    assert first.status_code == 201, first.text

    second = create_team(headers, code=code)

    assert second.status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "A", "code": "VALID-TEAM"},
        {"name": "Valid Team", "code": "A"},
        {"name": "Valid Team", "code": "INVALID CODE"},
        {
            "name": "Valid Team",
            "code": "VALID-TEAM",
            "description": "x" * 2001,
        },
    ],
)
def test_invalid_team_payload_is_rejected(payload):
    _, headers = register_and_login("SUPER_ADMIN")

    response = client.post(
        "/api/v1/security-teams",
        headers=headers,
        json=payload,
    )

    assert response.status_code == 422, response.text


def test_unexpected_team_field_is_ignored():
    _, headers = register_and_login("SUPER_ADMIN")

    response = client.post(
        "/api/v1/security-teams",
        headers=headers,
        json={
            "name": "Valid Team",
            "code": f"EXTRA-{uuid.uuid4().hex[:8].upper()}",
            "unexpected": "value",
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["name"] == "Valid Team"
    assert "unexpected" not in response.json()


def test_list_security_teams():
    _, headers = register_and_login("SUPER_ADMIN")
    created = create_team(headers)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/security-teams",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)
    assert any(
        item["id"] == created.json()["id"]
        for item in response.json()
    )


def test_list_teams_requires_authentication():
    response = client.get("/api/v1/security-teams")

    assert response.status_code in (401, 403)


def test_search_security_teams():
    _, headers = register_and_login("SUPER_ADMIN")
    code = f"SEARCH-{uuid.uuid4().hex[:8].upper()}"

    created = create_team(headers, code=code)
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/security-teams",
        headers=headers,
        params={"search": code},
    )

    assert response.status_code == 200, response.text
    assert any(item["code"] == code for item in response.json())


def test_get_security_team_by_id():
    _, headers = register_and_login("SUPER_ADMIN")
    created = create_team(headers)
    assert created.status_code == 201, created.text

    team_id = created.json()["id"]
    response = client.get(
        f"/api/v1/security-teams/{team_id}",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == team_id


def test_missing_team_returns_404():
    _, headers = register_and_login("SUPER_ADMIN")

    response = client.get(
        "/api/v1/security-teams/999999999",
        headers=headers,
    )

    assert response.status_code == 404


def test_update_team_name():
    _, headers = register_and_login("SUPER_ADMIN")
    created = create_team(headers)
    assert created.status_code == 201, created.text

    team_id = created.json()["id"]
    new_name = f"Updated Team {uuid.uuid4().hex[:8]}"

    response = client.patch(
        f"/api/v1/security-teams/{team_id}",
        headers=headers,
        json={"name": new_name},
    )

    assert response.status_code == 200, response.text
    assert response.json()["name"] == new_name


def test_update_team_active_status():
    _, headers = register_and_login("SUPER_ADMIN")
    created = create_team(headers)
    assert created.status_code == 201, created.text

    team_id = created.json()["id"]

    response = client.patch(
        f"/api/v1/security-teams/{team_id}",
        headers=headers,
        json={"is_active": False},
    )

    assert response.status_code == 200, response.text
    assert response.json()["is_active"] is False


def test_analyst_cannot_update_team():
    _, admin_headers = register_and_login("SUPER_ADMIN")
    _, analyst_headers = register_and_login("SECURITY_ANALYST")

    created = create_team(admin_headers)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/security-teams/{created.json()['id']}",
        headers=analyst_headers,
        json={"name": "Unauthorized Update"},
    )

    assert response.status_code == 403


def test_update_missing_team_returns_404():
    _, headers = register_and_login("SUPER_ADMIN")

    response = client.patch(
        "/api/v1/security-teams/999999999",
        headers=headers,
        json={"name": "Updated Team"},
    )

    assert response.status_code == 404


def test_assign_analyst_to_team():
    _, admin_headers = register_and_login("SUPER_ADMIN")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(admin_headers)
    assert created.status_code == 201, created.text
    team_id = created.json()["id"]

    response = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=admin_headers,
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 201, response.text
    assert response.json()["team_id"] == team_id
    assert response.json()["user_id"] == analyst["id"]


def test_security_manager_can_assign_analyst():
    _, admin_headers = register_and_login("SECURITY_MANAGER")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(admin_headers)
    assert created.status_code == 201, created.text

    response = client.post(
        f"/api/v1/security-teams/{created.json()['id']}/analysts",
        headers=admin_headers,
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 201, response.text


def test_cannot_assign_same_analyst_twice():
    _, headers = register_and_login("SUPER_ADMIN")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(headers)
    assert created.status_code == 201, created.text
    team_id = created.json()["id"]

    payload = {"user_id": analyst["id"]}

    first = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
        json=payload,
    )
    assert first.status_code == 201, first.text

    second = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
        json=payload,
    )

    assert second.status_code == 409


def test_cannot_assign_viewer_to_team():
    _, headers = register_and_login("SUPER_ADMIN")
    viewer, _ = register_and_login("VIEWER")

    created = create_team(headers)
    assert created.status_code == 201, created.text

    response = client.post(
        f"/api/v1/security-teams/{created.json()['id']}/analysts",
        headers=headers,
        json={"user_id": viewer["id"]},
    )

    assert response.status_code == 422


def test_assign_missing_user_returns_404():
    _, headers = register_and_login("SUPER_ADMIN")
    created = create_team(headers)
    assert created.status_code == 201, created.text

    response = client.post(
        f"/api/v1/security-teams/{created.json()['id']}/analysts",
        headers=headers,
        json={"user_id": 999999999},
    )

    assert response.status_code == 404


def test_assign_analyst_requires_manager_role():
    _, admin_headers = register_and_login("SUPER_ADMIN")
    _, analyst_headers = register_and_login("SECURITY_ANALYST")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(admin_headers)
    assert created.status_code == 201, created.text

    response = client.post(
        f"/api/v1/security-teams/{created.json()['id']}/analysts",
        headers=analyst_headers,
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 403


def test_assign_to_inactive_team_is_rejected():
    _, headers = register_and_login("SUPER_ADMIN")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(headers)
    assert created.status_code == 201, created.text
    team_id = created.json()["id"]

    updated = client.patch(
        f"/api/v1/security-teams/{team_id}",
        headers=headers,
        json={"is_active": False},
    )
    assert updated.status_code == 200, updated.text

    response = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 400


def test_list_team_analysts():
    _, headers = register_and_login("SUPER_ADMIN")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(headers)
    assert created.status_code == 201, created.text
    team_id = created.json()["id"]

    assigned = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
        json={"user_id": analyst["id"]},
    )
    assert assigned.status_code == 201, assigned.text

    response = client.get(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert any(
        item["user_id"] == analyst["id"]
        for item in response.json()
    )


def test_list_members_of_missing_team_returns_404():
    _, headers = register_and_login("SUPER_ADMIN")

    response = client.get(
        "/api/v1/security-teams/999999999/analysts",
        headers=headers,
    )

    assert response.status_code == 404


def test_remove_analyst_from_team():
    _, headers = register_and_login("SUPER_ADMIN")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(headers)
    assert created.status_code == 201, created.text
    team_id = created.json()["id"]

    assigned = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
        json={"user_id": analyst["id"]},
    )
    assert assigned.status_code == 201, assigned.text

    response = client.delete(
        f"/api/v1/security-teams/{team_id}/analysts/{analyst['id']}",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    members = client.get(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
    )
    assert members.status_code == 200, members.text
    assert all(
        item["user_id"] != analyst["id"]
        for item in members.json()
    )


def test_remove_nonexistent_membership_returns_404():
    _, headers = register_and_login("SUPER_ADMIN")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(headers)
    assert created.status_code == 201, created.text

    response = client.delete(
        f"/api/v1/security-teams/{created.json()['id']}/analysts/{analyst['id']}",
        headers=headers,
    )

    assert response.status_code == 404


def test_analyst_cannot_remove_team_member():
    _, admin_headers = register_and_login("SUPER_ADMIN")
    _, analyst_headers = register_and_login("SECURITY_ANALYST")
    analyst, _ = register_and_login("SECURITY_ANALYST")

    created = create_team(admin_headers)
    assert created.status_code == 201, created.text
    team_id = created.json()["id"]

    assigned = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=admin_headers,
        json={"user_id": analyst["id"]},
    )
    assert assigned.status_code == 201, assigned.text

    response = client.delete(
        f"/api/v1/security-teams/{team_id}/analysts/{analyst['id']}",
        headers=analyst_headers,
    )

    assert response.status_code == 403


def test_active_only_filter():
    _, headers = register_and_login("SUPER_ADMIN")

    active = create_team(headers)
    inactive = create_team(headers)

    assert active.status_code == 201, active.text
    assert inactive.status_code == 201, inactive.text

    update = client.patch(
        f"/api/v1/security-teams/{inactive.json()['id']}",
        headers=headers,
        json={"is_active": False},
    )
    assert update.status_code == 200, update.text

    response = client.get(
        "/api/v1/security-teams",
        headers=headers,
        params={"active_only": True},
    )

    assert response.status_code == 200, response.text
    assert all(item["is_active"] for item in response.json())
