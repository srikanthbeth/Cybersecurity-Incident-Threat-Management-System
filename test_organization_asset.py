
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

import models.organization
import models.asset


client = TestClient(app)


def unique_email():
    return f"user_{uuid4().hex[:10]}@example.com"


def unique_code(prefix="ORG"):
    return f"{prefix}-{uuid4().hex[:10].upper()}"


def cleanup_database():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                TRUNCATE TABLE
                    assets,
                    organizations,
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
        json={"email": email, "password": password},
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


def create_organization(token, code=None, name="Test Organization"):
    return client.post(
        "/api/v1/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": name,
            "code": code or unique_code(),
            "description": "Organization for integration testing",
            "industry": "Technology",
            "contact_email": "contact@example.com",
        },
    )


def create_asset(token, organization_id, asset_tag=None, **overrides):
    payload = {
        "organization_id": organization_id,
        "asset_tag": asset_tag or unique_code("AST"),
        "name": "Test Production Server",
        "asset_type": "SERVER",
        "description": "Integration test asset",
        "ip_address": "192.168.1.10",
        "hostname": "test-server.example.local",
        "operating_system": "Ubuntu Linux",
        "criticality": "HIGH",
        "status": "ACTIVE",
        "location": "Data Center 1",
    }
    payload.update(overrides)

    return client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )


def test_super_admin_can_create_organization():
    token = create_admin()

    response = create_organization(token)

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["name"] == "Test Organization"
    assert data["code"].startswith("ORG-")
    assert data["is_active"] is True
    assert data["created_by"] is not None


def test_security_analyst_cannot_create_organization():
    register_response = register_user()
    assert register_response.status_code == 201, register_response.text

    email = register_response.json()["email"]
    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text
    token = login_response.json()["access_token"]

    response = create_organization(token)

    assert response.status_code == 403, response.text


def test_organization_creation_requires_authentication():
    response = client.post(
        "/api/v1/organizations",
        json={
            "name": "Unauthorized Organization",
            "code": unique_code(),
        },
    )

    assert response.status_code == 401


def test_duplicate_organization_code_rejected():
    token = create_admin()
    code = unique_code()

    first = create_organization(token, code=code)
    assert first.status_code == 201, first.text

    second = create_organization(
        token,
        code=code.lower(),
        name="Duplicate Organization",
    )

    assert second.status_code == 409, second.text


def test_organization_code_is_normalized():
    token = create_admin()
    code = unique_code().lower()

    response = create_organization(token, code=code)

    assert response.status_code == 201, response.text
    assert response.json()["code"] == code.upper()


def test_organization_code_validation():
    token = create_admin()

    response = client.post(
        "/api/v1/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Invalid Code Organization",
            "code": "invalid code!",
        },
    )

    assert response.status_code == 422


def test_list_organizations():
    token = create_admin()

    first = create_organization(token, name="Alpha Security")
    second = create_organization(token, name="Beta Security")

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text

    response = client.get(
        "/api/v1/organizations",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    names = [item["name"] for item in response.json()]
    assert "Alpha Security" in names
    assert "Beta Security" in names


def test_search_organizations():
    token = create_admin()

    response = create_organization(
        token,
        name="Unique Search Organization",
    )
    assert response.status_code == 201, response.text

    result = client.get(
        "/api/v1/organizations",
        params={"search": "Unique Search"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert result.status_code == 200, result.text
    assert any(
        item["name"] == "Unique Search Organization"
        for item in result.json()
    )


def test_get_organization_by_id():
    token = create_admin()
    created = create_organization(token)
    assert created.status_code == 201, created.text

    organization_id = created.json()["id"]

    response = client.get(
        f"/api/v1/organizations/{organization_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == organization_id


def test_get_missing_organization():
    token = create_admin()

    response = client.get(
        "/api/v1/organizations/999999",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404


def test_update_organization():
    token = create_admin()
    created = create_organization(token)
    assert created.status_code == 201, created.text

    organization_id = created.json()["id"]

    response = client.patch(
        f"/api/v1/organizations/{organization_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Updated Security Organization",
            "industry": "Cybersecurity",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["name"] == "Updated Security Organization"
    assert response.json()["industry"] == "Cybersecurity"


def test_security_analyst_cannot_update_organization():
    admin_token = create_admin()
    created = create_organization(admin_token)
    assert created.status_code == 201, created.text

    register_response = register_user()
    assert register_response.status_code == 201, register_response.text
    email = register_response.json()["email"]

    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text
    analyst_token = login_response.json()["access_token"]

    response = client.patch(
        f"/api/v1/organizations/{created.json()['id']}",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"name": "Unauthorized Update"},
    )

    assert response.status_code == 403


def test_create_asset():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    response = create_asset(token, organization.json()["id"])

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["organization_id"] == organization.json()["id"]
    assert data["asset_type"] == "SERVER"
    assert data["criticality"] == "HIGH"
    assert data["status"] == "ACTIVE"
    assert data["ip_address"] == "192.168.1.10"


def test_asset_creation_requires_authentication():
    response = client.post(
        "/api/v1/assets",
        json={
            "organization_id": 1,
            "asset_tag": unique_code("AST"),
            "name": "Unauthorized Server",
            "asset_type": "SERVER",
        },
    )

    assert response.status_code == 401


def test_security_analyst_can_create_asset():
    admin_token = create_admin()
    organization = create_organization(admin_token)
    assert organization.status_code == 201, organization.text

    register_response = register_user()
    assert register_response.status_code == 201, register_response.text
    email = register_response.json()["email"]

    login_response = login_user(email)
    assert login_response.status_code == 200, login_response.text
    analyst_token = login_response.json()["access_token"]

    response = create_asset(
        analyst_token,
        organization.json()["id"],
    )

    assert response.status_code == 201, response.text


def test_duplicate_asset_tag_rejected_within_organization():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text
    organization_id = organization.json()["id"]
    tag = unique_code("AST")

    first = create_asset(token, organization_id, asset_tag=tag)
    assert first.status_code == 201, first.text

    second = create_asset(
        token,
        organization_id,
        asset_tag=tag.lower(),
        name="Duplicate Asset",
    )

    assert second.status_code == 409, second.text


def test_same_asset_tag_allowed_in_different_organizations():
    token = create_admin()
    first_org = create_organization(token)
    second_org = create_organization(token)

    assert first_org.status_code == 201, first_org.text
    assert second_org.status_code == 201, second_org.text

    tag = unique_code("AST")

    first = create_asset(token, first_org.json()["id"], asset_tag=tag)
    second = create_asset(token, second_org.json()["id"], asset_tag=tag)

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text


def test_create_asset_for_missing_organization():
    token = create_admin()

    response = create_asset(token, 999999)

    assert response.status_code == 404, response.text


def test_create_asset_for_inactive_organization():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    update = client.patch(
        f"/api/v1/organizations/{organization.json()['id']}",
        headers={"Authorization": f"Bearer {token}"},
        json={"is_active": False},
    )
    assert update.status_code == 200, update.text

    response = create_asset(token, organization.json()["id"])

    assert response.status_code == 400, response.text


def test_invalid_asset_ip_address():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    response = create_asset(
        token,
        organization.json()["id"],
        ip_address="not-an-ip-address",
    )

    assert response.status_code == 422, response.text


def test_invalid_asset_type():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    response = create_asset(
        token,
        organization.json()["id"],
        asset_type="UNKNOWN_DEVICE",
    )

    assert response.status_code == 422, response.text


def test_invalid_asset_criticality():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    response = create_asset(
        token,
        organization.json()["id"],
        criticality="EXTREME",
    )

    assert response.status_code == 422, response.text


def test_list_assets():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    created = create_asset(token, organization.json()["id"])
    assert created.status_code == 201, created.text

    response = client.get(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert any(
        item["id"] == created.json()["id"]
        for item in response.json()
    )


def test_filter_assets_by_organization():
    token = create_admin()
    first_org = create_organization(token)
    second_org = create_organization(token)

    assert first_org.status_code == 201, first_org.text
    assert second_org.status_code == 201, second_org.text

    first_asset = create_asset(token, first_org.json()["id"])
    second_asset = create_asset(token, second_org.json()["id"])

    assert first_asset.status_code == 201, first_asset.text
    assert second_asset.status_code == 201, second_asset.text

    response = client.get(
        "/api/v1/assets",
        params={"organization_id": first_org.json()["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert all(
        item["organization_id"] == first_org.json()["id"]
        for item in response.json()
    )
    assert any(
        item["id"] == first_asset.json()["id"]
        for item in response.json()
    )
    assert all(
        item["id"] != second_asset.json()["id"]
        for item in response.json()
    )


def test_filter_assets_by_type():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text
    organization_id = organization.json()["id"]

    server = create_asset(
        token,
        organization_id,
        asset_type="SERVER",
    )
    endpoint = create_asset(
        token,
        organization_id,
        asset_type="ENDPOINT",
    )

    assert server.status_code == 201, server.text
    assert endpoint.status_code == 201, endpoint.text

    response = client.get(
        "/api/v1/assets",
        params={"asset_type": "SERVER"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert all(item["asset_type"] == "SERVER" for item in response.json())


def test_filter_assets_by_criticality():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text
    organization_id = organization.json()["id"]

    high = create_asset(
        token,
        organization_id,
        criticality="HIGH",
    )
    low = create_asset(
        token,
        organization_id,
        criticality="LOW",
    )

    assert high.status_code == 201, high.text
    assert low.status_code == 201, low.text

    response = client.get(
        "/api/v1/assets",
        params={"criticality": "HIGH"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert all(
        item["criticality"] == "HIGH"
        for item in response.json()
    )


def test_filter_assets_by_status():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text
    organization_id = organization.json()["id"]

    active = create_asset(
        token,
        organization_id,
        status="ACTIVE",
    )
    retired = create_asset(
        token,
        organization_id,
        status="RETIRED",
    )

    assert active.status_code == 201, active.text
    assert retired.status_code == 201, retired.text

    response = client.get(
        "/api/v1/assets",
        params={"status": "RETIRED"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert all(item["status"] == "RETIRED" for item in response.json())


def test_search_assets():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    asset = create_asset(
        token,
        organization.json()["id"],
        name="Unique Search Server",
    )
    assert asset.status_code == 201, asset.text

    response = client.get(
        "/api/v1/assets",
        params={"search": "Unique Search"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert any(
        item["name"] == "Unique Search Server"
        for item in response.json()
    )


def test_get_asset_by_id():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    asset = create_asset(token, organization.json()["id"])
    assert asset.status_code == 201, asset.text

    response = client.get(
        f"/api/v1/assets/{asset.json()['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == asset.json()["id"]


def test_get_missing_asset():
    token = create_admin()

    response = client.get(
        "/api/v1/assets/999999",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404


def test_update_asset():
    token = create_admin()
    organization = create_organization(token)
    assert organization.status_code == 201, organization.text

    asset = create_asset(token, organization.json()["id"])
    assert asset.status_code == 201, asset.text

    response = client.patch(
        f"/api/v1/assets/{asset.json()['id']}",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Updated Production Server",
            "criticality": "CRITICAL",
            "status": "UNDER_MAINTENANCE",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["name"] == "Updated Production Server"
    assert response.json()["criticality"] == "CRITICAL"
    assert response.json()["status"] == "UNDER_MAINTENANCE"


def test_security_analyst_cannot_update_asset():
    admin_token = create_admin()
    organization = create_organization(admin_token)
    assert organization.status_code == 201, organization.text

    asset = create_asset(admin_token, organization.json()["id"])
    assert asset.status_code == 201, asset.text

    register_response = register_user()
    assert register_response.status_code == 201, register_response.text

    login_response = login_user(register_response.json()["email"])
    assert login_response.status_code == 200, login_response.text
    analyst_token = login_response.json()["access_token"]

    response = client.patch(
        f"/api/v1/assets/{asset.json()['id']}",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"name": "Unauthorized Update"},
    )

    assert response.status_code == 403
