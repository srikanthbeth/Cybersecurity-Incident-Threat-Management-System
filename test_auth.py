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


client = TestClient(app)


def unique_email():
    return f"user_{uuid4().hex[:10]}@example.com"


def cleanup_database():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                TRUNCATE TABLE
                    password_reset_tokens,
                    revoked_tokens,
                    users
                RESTART IDENTITY CASCADE
                """
            )
        )


def setup_module():
    Base.metadata.create_all(bind=engine)
    cleanup_database()


def teardown_module():
    cleanup_database()


def register_user(email=None, password="StrongPassword123!"):
    if email is None:
        email = unique_email()

    return client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Test Analyst",
            "email": email,
            "password": password,
        },
    )


def login_user(email, password="StrongPassword123!"):
    return client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )


def create_admin():
    from core.security import hash_password
    from models.user import User

    email = unique_email()
    db = SessionLocal()

    try:
        admin = User(
            full_name="Test Super Admin",
            email=email,
            password_hash=hash_password("AdminPassword123!"),
            role="SUPER_ADMIN",
            is_active=True,
        )

        db.add(admin)
        db.commit()
    finally:
        db.close()

    response = login_user(email, "AdminPassword123!")
    assert response.status_code == 200, response.text

    return response.json()["access_token"]


def test_register_user():
    response = register_user()

    assert response.status_code == 201, response.text

    data = response.json()

    assert data["full_name"] == "Test Analyst"
    assert data["email"].endswith("@example.com")
    assert data["role"] == "SECURITY_ANALYST"


def test_public_registration_cannot_select_admin_role():
    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Attempted Admin",
            "email": unique_email(),
            "password": "StrongPassword123!",
            "role": "SUPER_ADMIN",
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["role"] == "SECURITY_ANALYST"


def test_duplicate_email():
    email = unique_email()

    first = register_user(email)
    assert first.status_code == 201, first.text

    second = register_user(email)

    assert second.status_code == 409
    assert second.json()["detail"] == (
    "An account with this email already exists."
)


def test_password_is_hashed():
    from models.user import User

    email = unique_email()
    response = register_user(email)

    assert response.status_code == 201, response.text

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()

        assert user is not None
        assert user.password_hash != "StrongPassword123!"

        from core.security import verify_password

        assert verify_password(
            "StrongPassword123!",
            user.password_hash,
        )
    finally:
        db.close()


def test_login_success():
    email = unique_email()
    register_response = register_user(email)
    assert register_response.status_code == 201, register_response.text

    response = login_user(email)

    assert response.status_code == 200, response.text

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_invalid_password():
    email = unique_email()
    register_user(email)

    response = login_user(email, "WrongPassword123!")

    assert response.status_code == 401


def test_current_user():
    email = unique_email()
    register_user(email)

    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["email"] == email
    assert response.json()["role"] == "SECURITY_ANALYST"


def test_missing_authentication():
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_invalid_access_token():
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_refresh_token():
    email = unique_email()
    register_user(email)

    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text

    refresh_token = login_response.json()["refresh_token"]

    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["refresh_token"] != refresh_token


def test_old_refresh_token_cannot_be_reused():
    email = unique_email()
    register_user(email)

    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text

    old_refresh_token = login_response.json()["refresh_token"]

    first_refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh_token},
    )

    assert first_refresh.status_code == 200, first_refresh.text

    second_refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh_token},
    )

    assert second_refresh.status_code == 401


def test_invalid_refresh_token():
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid-refresh-token"},
    )

    assert response.status_code == 401


def test_logout():
    email = unique_email()
    register_user(email)

    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text

    data = login_response.json()

    response = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": data["refresh_token"]},
        headers={
            "Authorization": f"Bearer {data['access_token']}"
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["message"] == "Logged out successfully."

    me_response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": f"Bearer {data['access_token']}"
        },
    )

    assert me_response.status_code == 401


def test_password_reset_request():
    email = unique_email()
    register_user(email)

    response = client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": email},
    )

    assert response.status_code == 200, response.text
    assert response.json()["message"] == (
    "If an active account exists for this email, "
    "password reset instructions will be sent."
)
    assert response.json().get("reset_token")


def test_password_reset_unknown_email():
    response = client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": unique_email()},
    )

    assert response.status_code == 200
    assert response.json()["message"] == (
    "If an active account exists for this email, "
    "password reset instructions will be sent."
)


def test_password_reset_changes_password():
    email = unique_email()
    register_user(email)

    reset_response = client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": email},
    )

    assert reset_response.status_code == 200, reset_response.text
    reset_token = reset_response.json().get("reset_token")
    assert reset_token

    response = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "token": reset_token,
            "new_password": "NewStrongPassword456!",
        },
    )

    assert response.status_code == 200, response.text

    old_login = login_user(email, "StrongPassword123!")
    assert old_login.status_code == 401

    new_login = login_user(email, "NewStrongPassword456!")
    assert new_login.status_code == 200, new_login.text


def test_invalid_password_reset_token():
    response = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "token": "invalid-reset-token-12345",
            "new_password": "NewStrongPassword456!",
        },
    )

    assert response.status_code == 400


def test_worker_cannot_update_user_status():
    email = unique_email()
    register_user(email)

    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["access_token"]

    target_response = register_user()
    assert target_response.status_code == 201, target_response.text

    target_id = target_response.json()["id"]

    response = client.patch(
        f"/api/v1/users/{target_id}/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_super_admin_can_update_user_status():
    token = create_admin()

    target_response = register_user()
    assert target_response.status_code == 201, target_response.text

    target_id = target_response.json()["id"]

    response = client.patch(
        f"/api/v1/users/{target_id}/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["is_active"] is False


def test_super_admin_can_update_user_role():
    token = create_admin()

    target_response = register_user()
    assert target_response.status_code == 201, target_response.text

    target_id = target_response.json()["id"]

    response = client.patch(
        f"/api/v1/users/{target_id}/role",
        json={"role": "INCIDENT_RESPONDER"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["role"] == "INCIDENT_RESPONDER"


def test_inactive_user_cannot_login():
    from models.user import User

    email = unique_email()
    register_response = register_user(email)
    assert register_response.status_code == 201, register_response.text

    user_id = register_response.json()["id"]

    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        assert user is not None
        user.is_active = False
        db.commit()
    finally:
        db.close()

    response = login_user(email)

    assert response.status_code == 403
