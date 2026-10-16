
import os
from uuid import uuid4

os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://postgres:Srik8499@localhost:5433/"
    "cybersecurity_incident_threat_test"
)
os.environ["ENVIRONMENT"] = "development"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from core.security import hash_password
from database import Base, SessionLocal, engine
from main import app
from models.audit_log import AuditLog
from models.user import User
from schemas.audit_log import AuditLogCreate
from services.audit_log_service import AuditLogService


client = TestClient(app)


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def unique_email():
    return f"audit_{uuid4().hex[:10]}@example.com"


def cleanup_audit_logs():
    """Clear audit records before and after each test."""
    with engine.begin() as connection:
        connection.execute(
            text("TRUNCATE TABLE audit_logs RESTART IDENTITY CASCADE")
        )


def cleanup_database():
    """Clean test users and authentication records."""
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                TRUNCATE TABLE
                    audit_logs,
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


@pytest.fixture(autouse=True)
def isolate_audit_logs():
    cleanup_audit_logs()
    yield
    cleanup_audit_logs()


def create_user(role="SECURITY_ANALYST"):
    """Create a user and return its access token."""
    email = unique_email()
    password = "AuditTestPassword123!"

    db = SessionLocal()

    try:
        user = User(
            full_name="Audit Test User",
            email=email,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )

        db.add(user)
        db.commit()
    finally:
        db.close()

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 200, response.text

    return response.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_audit_record(
    *,
    user_id=None,
    action="TEST_ACTION",
    entity_type="TEST_ENTITY",
    entity_id="100",
    previous_value=None,
    new_value=None,
):
    """Create an audit record using the audit service."""
    db = SessionLocal()

    try:
        payload = AuditLogCreate(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            previous_value=previous_value,
            new_value=new_value,
        )

        log = AuditLogService.create(db, payload)

        db.commit()
        db.refresh(log)

        return log.id
    finally:
        db.close()


def print_audit_chain_diagnostics():
    """Print stored hashes and independently recalculated hashes."""
    db = SessionLocal()

    try:
        logs = (
            db.query(AuditLog)
            .order_by(AuditLog.id.asc())
            .all()
        )

        print("\n========== AUDIT CHAIN DIAGNOSTICS ==========")

        expected_previous_hash = None

        for log in logs:
            calculated_hash = AuditLogService.calculate_hash(log)

            print(
                f"\nID: {log.id}\n"
                f"Action: {log.action}\n"
                f"Previous hash: {log.previous_hash}\n"
                f"Expected previous hash: {expected_previous_hash}\n"
                f"Stored hash: {log.record_hash}\n"
                f"Calculated hash: {calculated_hash}\n"
                f"Link matches: "
                f"{log.previous_hash == expected_previous_hash}\n"
                f"Hash matches: "
                f"{log.record_hash == calculated_hash}"
            )

            expected_previous_hash = log.record_hash

        print("=============================================\n")

    finally:
        db.close()


# ---------------------------------------------------------
# AUTHENTICATION AND AUTHORIZATION TESTS
# ---------------------------------------------------------

def test_audit_logs_require_authentication():
    response = client.get("/api/v1/audit-logs")

    assert response.status_code == 401


def test_analyst_cannot_list_audit_logs():
    token = create_user("SECURITY_ANALYST")

    response = client.get(
        "/api/v1/audit-logs",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


# ---------------------------------------------------------
# AUDIT LOG LIST AND DETAIL TESTS
# ---------------------------------------------------------

def test_super_admin_can_list_audit_logs():
    token = create_user("SUPER_ADMIN")

    create_audit_record(
        action="LOGIN",
        entity_type="USER",
    )

    response = client.get(
        "/api/v1/audit-logs",
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert "items" in data
    assert data["total"] >= 1
    assert any(
        item["action"] == "LOGIN"
        for item in data["items"]
    )


def test_super_admin_can_get_audit_log():
    token = create_user("SUPER_ADMIN")

    audit_id = create_audit_record(
        action="INCIDENT_UPDATED",
        entity_type="INCIDENT",
        entity_id="42",
        new_value={"status": "INVESTIGATING"},
    )

    response = client.get(
        f"/api/v1/audit-logs/{audit_id}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["id"] == audit_id
    assert data["action"] == "INCIDENT_UPDATED"
    assert data["entity_type"] == "INCIDENT"
    assert data["entity_id"] == "42"


def test_missing_audit_log_returns_404():
    token = create_user("SUPER_ADMIN")

    response = client.get(
        "/api/v1/audit-logs/99999999",
        headers=auth_headers(token),
    )

    assert response.status_code == 404


# ---------------------------------------------------------
# HASH CHAIN VERIFICATION TESTS
# ---------------------------------------------------------

def test_audit_hash_chain_verifies():
    token = create_user("SUPER_ADMIN")

    first_id = create_audit_record(
        action="FIRST_EVENT",
        entity_type="TEST_ENTITY",
        entity_id="101",
        new_value={"event": "first"},
    )

    second_id = create_audit_record(
        action="SECOND_EVENT",
        entity_type="TEST_ENTITY",
        entity_id="102",
        new_value={"event": "second"},
    )

    response = client.get(
        "/api/v1/audit-logs/verify",
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.text

    data = response.json()

    print("\nAUDIT CHAIN VERIFICATION RESULT:", data)
    print_audit_chain_diagnostics()

    assert data["valid"] is True, (
        f"Audit chain verification failed: {data}"
    )
    assert data["checked_records"] == 2
    assert data["first_invalid_record_id"] is None

    db = SessionLocal()

    try:
        first = db.get(AuditLog, first_id)
        second = db.get(AuditLog, second_id)

        assert first is not None
        assert second is not None

        assert first.previous_hash is None
        assert second.previous_hash == first.record_hash

    finally:
        db.close()


def test_analyst_cannot_verify_audit_chain():
    token = create_user("SECURITY_ANALYST")

    response = client.get(
        "/api/v1/audit-logs/verify",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_audit_hash_chain_detects_record_tampering():
    token = create_user("SUPER_ADMIN")

    audit_id = create_audit_record(
        action="ORIGINAL_ACTION",
        entity_type="TEST_ENTITY",
        entity_id="200",
        new_value={"status": "OPEN"},
    )

    db = SessionLocal()

    try:
        record = db.get(AuditLog, audit_id)

        assert record is not None

        # Simulate unauthorized modification without recalculating
        # the record hash.
        record.action = "TAMPERED_ACTION"
        db.commit()

    finally:
        db.close()

    response = client.get(
        "/api/v1/audit-logs/verify",
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.text

    data = response.json()

    print("\nTAMPER DETECTION RESULT:", data)
    print_audit_chain_diagnostics()

    assert data["valid"] is False
    assert data["first_invalid_record_id"] == audit_id
