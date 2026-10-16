
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
from models.security_team import SecurityTeam, SecurityTeamMember
from models.user import User


client = TestClient(app)
PASSWORD = "StrongPassword123!"


def cleanup_database():
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE security_team_members, security_teams, "
                "assets, organizations, password_reset_tokens, "
                "revoked_tokens, users RESTART IDENTITY CASCADE"
            )
        )


def setup_module():
    Base.metadata.create_all(bind=engine)
    cleanup_database()


def teardown_module():
    cleanup_database()


def unique_email():
    return f"user_{uuid4().hex[:12]}@example.com"


def register_user(role="SECURITY_ANALYST", active=True):
    email = unique_email()

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Test Security User",
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

    return {
        "id": user_id,
        "email": email,
        "password": PASSWORD,
        "role": role,
        "is_active": active,
    }


def login_user(user):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": user["email"],
            "password": user["password"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def create_user_and_token(role="SECURITY_ANALYST", active=True):
    user = register_user(role=role, active=active)
    token = login_user(user) if active else None
    return user, token


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_team(token, code=None):
    return client.post(
        "/api/v1/security-teams",
        headers=auth_headers(token),
        json={
            "name": "Incident Response Team",
            "code": code or f"TEAM-{uuid4().hex[:8].upper()}",
            "description": "Security operations and incident response",
        },
    )


def test_admin_can_list_users():
    _, admin_token = create_user_and_token("SUPER_ADMIN")
    create_user_and_token("SECURITY_ANALYST")

    response = client.get(
        "/api/v1/users",
        headers=auth_headers(admin_token),
    )

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)
    assert len(response.json()) >= 2


def test_security_manager_can_list_users():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")

    response = client.get(
        "/api/v1/users",
        headers=auth_headers(manager_token),
    )

    assert response.status_code == 200, response.text


def test_analyst_cannot_list_users():
    _, token = create_user_and_token("SECURITY_ANALYST")

    response = client.get(
        "/api/v1/users",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_user_list_requires_authentication():
    response = client.get("/api/v1/users")
    assert response.status_code == 401


def test_user_list_search_and_pagination():
    _, token = create_user_and_token("SUPER_ADMIN")

    response = client.get(
        "/api/v1/users",
        params={"search": "Test Security User", "page": 1, "page_size": 5},
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.text
    assert len(response.json()) <= 5
    assert all(
        "Test Security User" in user["full_name"]
        for user in response.json()
    )


def test_user_list_can_filter_by_role():
    _, token = create_user_and_token("SUPER_ADMIN")
    create_user_and_token("SECURITY_ANALYST")

    response = client.get(
        "/api/v1/users",
        params={"role": "SECURITY_ANALYST"},
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.text
    assert all(
        user["role"] == "SECURITY_ANALYST"
        for user in response.json()
    )


def test_user_can_view_own_profile():
    user, token = create_user_and_token()

    response = client.get(
        "/api/v1/users/me",
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == user["id"]
    assert response.json()["email"] == user["email"]


def test_user_can_update_own_profile():
    user, token = create_user_and_token()

    response = client.patch(
        "/api/v1/users/me/profile",
        headers=auth_headers(token),
        json={"full_name": "Updated Analyst"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["full_name"] == "Updated Analyst"
    assert response.json()["id"] == user["id"]


def test_profile_update_rejects_short_name():
    _, token = create_user_and_token()

    response = client.patch(
        "/api/v1/users/me/profile",
        headers=auth_headers(token),
        json={"full_name": "A"},
    )

    assert response.status_code == 422


def test_admin_can_view_user_details():
    _, admin_token = create_user_and_token("SUPER_ADMIN")
    target, _ = create_user_and_token("SECURITY_ANALYST")

    response = client.get(
        f"/api/v1/users/{target['id']}",
        headers=auth_headers(admin_token),
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == target["id"]


def test_analyst_cannot_view_another_user_details():
    _, analyst_token = create_user_and_token("SECURITY_ANALYST")
    target, _ = create_user_and_token("SECURITY_ANALYST")

    response = client.get(
        f"/api/v1/users/{target['id']}",
        headers=auth_headers(analyst_token),
    )

    assert response.status_code == 403


def test_missing_user_returns_404():
    _, token = create_user_and_token("SUPER_ADMIN")

    response = client.get(
        "/api/v1/users/999999",
        headers=auth_headers(token),
    )

    assert response.status_code == 404


def test_super_admin_can_create_security_team():
    _, token = create_user_and_token("SUPER_ADMIN")

    response = create_team(token)

    assert response.status_code == 201, response.text
    assert response.json()["is_active"] is True


def test_security_manager_can_create_security_team():
    _, token = create_user_and_token("SECURITY_MANAGER")

    response = create_team(token)

    assert response.status_code == 201, response.text


def test_analyst_cannot_create_security_team():
    _, token = create_user_and_token("SECURITY_ANALYST")

    response = create_team(token)

    assert response.status_code == 403


def test_security_team_creation_requires_authentication():
    response = client.post(
        "/api/v1/security-teams",
        json={
            "name": "Unauthorized Team",
            "code": "UNAUTHORIZED-TEAM",
        },
    )

    assert response.status_code == 401


def test_duplicate_security_team_code_is_rejected():
    _, token = create_user_and_token("SUPER_ADMIN")
    code = f"DUP-{uuid4().hex[:8].upper()}"

    first = create_team(token, code)
    assert first.status_code == 201, first.text

    second = create_team(token, code)
    assert second.status_code == 409


def test_security_team_code_is_normalized():
    _, token = create_user_and_token("SUPER_ADMIN")
    code = f"team-{uuid4().hex[:8]}"

    response = create_team(token, code)

    assert response.status_code == 201, response.text
    assert response.json()["code"] == code.upper()


def test_authenticated_user_can_list_security_teams():
    _, admin_token = create_user_and_token("SUPER_ADMIN")
    _, analyst_token = create_user_and_token("SECURITY_ANALYST")
    create_team(admin_token)

    response = client.get(
        "/api/v1/security-teams",
        headers=auth_headers(analyst_token),
    )

    assert response.status_code == 200, response.text
    assert len(response.json()) >= 1


def test_security_team_search():
    _, admin_token = create_user_and_token("SUPER_ADMIN")
    name = f"Searchable-{uuid4().hex[:8]}"

    created = client.post(
        "/api/v1/security-teams",
        headers=auth_headers(admin_token),
        json={"name": name, "code": f"SEARCH-{uuid4().hex[:8]}"},
    )
    assert created.status_code == 201, created.text

    _, analyst_token = create_user_and_token("SECURITY_ANALYST")
    response = client.get(
        "/api/v1/security-teams",
        params={"search": name},
        headers=auth_headers(analyst_token),
    )

    assert response.status_code == 200, response.text
    assert any(team["name"] == name for team in response.json())


def test_manager_can_update_security_team():
    _, token = create_user_and_token("SECURITY_MANAGER")
    created = create_team(token)
    assert created.status_code == 201, created.text

    response = client.patch(
        f"/api/v1/security-teams/{created.json()['id']}",
        headers=auth_headers(token),
        json={"name": "Updated Response Team"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["name"] == "Updated Response Team"


def test_analyst_cannot_update_security_team():
    _, admin_token = create_user_and_token("SUPER_ADMIN")
    created = create_team(admin_token)
    assert created.status_code == 201, created.text

    _, analyst_token = create_user_and_token("SECURITY_ANALYST")
    response = client.patch(
        f"/api/v1/security-teams/{created.json()['id']}",
        headers=auth_headers(analyst_token),
        json={"name": "Unauthorized Team Update"},
    )

    assert response.status_code == 403


def test_manager_can_assign_analyst_to_team():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")
    analyst, _ = create_user_and_token("SECURITY_ANALYST")
    team = create_team(manager_token)
    assert team.status_code == 201, team.text

    response = client.post(
        f"/api/v1/security-teams/{team.json()['id']}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 201, response.text
    assert response.json()["user_id"] == analyst["id"]
    assert response.json()["team_id"] == team.json()["id"]


def test_analyst_cannot_assign_team_members():
    _, admin_token = create_user_and_token("SUPER_ADMIN")
    team = create_team(admin_token)
    assert team.status_code == 201, team.text

    analyst, analyst_token = create_user_and_token("SECURITY_ANALYST")
    target, _ = create_user_and_token("SECURITY_ANALYST")

    response = client.post(
        f"/api/v1/security-teams/{team.json()['id']}/analysts",
        headers=auth_headers(analyst_token),
        json={"user_id": target["id"]},
    )

    assert response.status_code == 403


def test_duplicate_analyst_assignment_is_rejected():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")
    analyst, _ = create_user_and_token("SECURITY_ANALYST")
    team = create_team(manager_token)
    assert team.status_code == 201, team.text
    team_id = team.json()["id"]

    first = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": analyst["id"]},
    )
    assert first.status_code == 201, first.text

    second = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": analyst["id"]},
    )

    assert second.status_code == 409


def test_non_analyst_cannot_be_assigned_to_team():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")
    viewer, _ = create_user_and_token("VIEWER")
    team = create_team(manager_token)
    assert team.status_code == 201, team.text

    response = client.post(
        f"/api/v1/security-teams/{team.json()['id']}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": viewer["id"]},
    )

    assert response.status_code == 422


def test_inactive_analyst_cannot_be_assigned():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")
    analyst, _ = create_user_and_token("SECURITY_ANALYST")
    team = create_team(manager_token)
    assert team.status_code == 201, team.text

    with SessionLocal() as db:
        user = db.get(User, analyst["id"])
        user.is_active = False
        db.commit()

    response = client.post(
        f"/api/v1/security-teams/{team.json()['id']}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 400


def test_manager_can_list_team_analysts():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")
    analyst, _ = create_user_and_token("SECURITY_ANALYST")
    team = create_team(manager_token)
    assert team.status_code == 201, team.text

    assignment = client.post(
        f"/api/v1/security-teams/{team.json()['id']}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": analyst["id"]},
    )
    assert assignment.status_code == 201, assignment.text

    response = client.get(
        f"/api/v1/security-teams/{team.json()['id']}/analysts",
        headers=auth_headers(manager_token),
    )

    assert response.status_code == 200, response.text
    assert any(member["user_id"] == analyst["id"] for member in response.json())


def test_manager_can_remove_team_analyst():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")
    analyst, _ = create_user_and_token("SECURITY_ANALYST")
    team = create_team(manager_token)
    assert team.status_code == 201, team.text
    team_id = team.json()["id"]

    assignment = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": analyst["id"]},
    )
    assert assignment.status_code == 201, assignment.text

    response = client.delete(
        f"/api/v1/security-teams/{team_id}/analysts/{analyst['id']}",
        headers=auth_headers(manager_token),
    )

    assert response.status_code == 200, response.text
    assert response.json()["message"] == "Analyst removed from security team."


def test_cannot_assign_analyst_to_inactive_team():
    _, manager_token = create_user_and_token("SECURITY_MANAGER")
    analyst, _ = create_user_and_token("SECURITY_ANALYST")
    team = create_team(manager_token)
    assert team.status_code == 201, team.text
    team_id = team.json()["id"]

    updated = client.patch(
        f"/api/v1/security-teams/{team_id}",
        headers=auth_headers(manager_token),
        json={"is_active": False},
    )
    assert updated.status_code == 200, updated.text

    response = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=auth_headers(manager_token),
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 400
