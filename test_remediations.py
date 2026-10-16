
import os
import uuid
from datetime import datetime, timedelta, timezone

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
    return f"remediation-{uuid.uuid4().hex[:10]}@example.com"


def register_and_login(role="SUPER_ADMIN"):
    email = unique_email()

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Remediation Tester",
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code in (200, 201), response.text

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        user.role = role
        db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text

    return {
        "Authorization": f"Bearer {response.json()['access_token']}"
    }


def create_organization(headers):
    code = f"RMD-{uuid.uuid4().hex[:8].upper()}"
    response = client.post(
        "/api/v1/organizations",
        headers=headers,
        json={
            "name": f"Remediation Test {code}",
            "code": code,
            "description": "Remediation integration test",
            "industry": "Technology",
            "contact_email": f"{code.lower()}@example.com",
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["id"]


def create_asset(headers, organization_id):
    tag = f"RMD-{uuid.uuid4().hex[:8].upper()}"
    response = client.post(
        "/api/v1/assets",
        headers=headers,
        json={
            "organization_id": organization_id,
            "asset_tag": tag,
            "name": f"Remediation Asset {tag}",
            "asset_type": "SERVER",
            "description": "Asset for remediation tests",
            "ip_address": "192.0.2.25",
            "hostname": tag.lower(),
            "operating_system": "Linux",
            "criticality": "HIGH",
            "status": "ACTIVE",
            "location": "Test environment",
        },
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["id"]


def create_team(headers):
    code = f"RMD-{uuid.uuid4().hex[:8].upper()}"
    response = client.post(
        "/api/v1/security-teams",
        headers=headers,
        json={
            "name": f"Remediation Team {code}",
            "code": code,
            "description": "Team for remediation integration tests",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def create_analyst_and_assign(headers, team_id):
    email = unique_email()

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Remediation Analyst",
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code in (200, 201), response.text

    with SessionLocal() as db:
        analyst = db.query(User).filter(User.email == email).first()
        assert analyst is not None
        analyst.role = "SECURITY_ANALYST"
        db.commit()
        analyst_id = analyst.id

    response = client.post(
        f"/api/v1/security-teams/{team_id}/analysts",
        headers=headers,
        json={"user_id": analyst_id},
    )
    assert response.status_code == 201, response.text

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": PASSWORD},
    )
    assert login_response.status_code == 200, login_response.text

    analyst_headers = {
        "Authorization": (
            f"Bearer {login_response.json()['access_token']}"
        )
    }
    return analyst_id, analyst_headers


def prepare_remediation():
    manager_headers = register_and_login("SUPER_ADMIN")
    organization_id = create_organization(manager_headers)
    asset_id = create_asset(manager_headers, organization_id)
    team_id = create_team(manager_headers)
    analyst_id, analyst_headers = create_analyst_and_assign(
        manager_headers, team_id
    )

    response = client.post(
        "/api/v1/remediations",
        headers=manager_headers,
        json={
            "title": "Patch vulnerable server",
            "description": "Apply the security patch and verify the fix.",
            "asset_id": asset_id,
            "assigned_team_id": team_id,
            "assigned_to": analyst_id,
            "priority": "HIGH",
            "due_at": (
                datetime.now(timezone.utc) + timedelta(days=7)
            ).isoformat(),
        },
    )
    assert response.status_code == 201, response.text

    return (
        manager_headers,
        analyst_headers,
        team_id,
        asset_id,
        response.json(),
    )


def test_create_remediation_success():
    _, _, _, _, task = prepare_remediation()

    assert task["task_number"].startswith("RMD-")
    assert task["status"] == "OPEN"
    assert task["priority"] == "HIGH"
    assert task["asset_id"] is not None


def test_create_remediation_requires_authentication():
    response = client.post(
        "/api/v1/remediations",
        json={},
    )
    assert response.status_code == 401


def test_viewer_cannot_create_remediation():
    headers = register_and_login("VIEWER")
    response = client.post(
        "/api/v1/remediations",
        headers=headers,
        json={
            "title": "Patch server",
            "description": "Apply the required patch.",
            "asset_id": 1,
            "assigned_team_id": 1,
            "priority": "HIGH",
            "due_at": (
                datetime.now(timezone.utc) + timedelta(days=3)
            ).isoformat(),
        },
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "overrides",
    [
        {"title": "AB"},
        {"description": "Bad"},
        {"priority": "URGENT"},
        {"asset_id": None, "vulnerability_id": None, "incident_id": None},
        {"assigned_team_id": 0},
    ],
)
def test_invalid_remediation_payload(overrides):
    headers = register_and_login("SUPER_ADMIN")
    organization_id = create_organization(headers)
    asset_id = create_asset(headers, organization_id)
    team_id = create_team(headers)

    payload = {
        "title": "Patch vulnerable server",
        "description": "Apply and verify the security patch.",
        "asset_id": asset_id,
        "assigned_team_id": team_id,
        "priority": "MEDIUM",
        "due_at": (
            datetime.now(timezone.utc) + timedelta(days=5)
        ).isoformat(),
    }
    payload.update(overrides)

    response = client.post(
        "/api/v1/remediations",
        headers=headers,
        json=payload,
    )
    assert response.status_code == 422, response.text


def test_list_remediations():
    headers, _, _, _, task = prepare_remediation()

    response = client.get(
        "/api/v1/remediations",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert any(item["id"] == task["id"] for item in response.json())


def test_filter_remediations_by_status():
    headers, _, _, _, task = prepare_remediation()

    response = client.get(
        "/api/v1/remediations",
        headers=headers,
        params={"status": "OPEN"},
    )
    assert response.status_code == 200, response.text
    assert all(item["status"] == "OPEN" for item in response.json())
    assert any(item["id"] == task["id"] for item in response.json())


def test_filter_remediations_by_priority():
    headers, _, _, _, task = prepare_remediation()

    response = client.get(
        "/api/v1/remediations",
        headers=headers,
        params={"priority": "HIGH"},
    )
    assert response.status_code == 200, response.text
    assert any(item["id"] == task["id"] for item in response.json())


def test_get_remediation_by_id():
    headers, _, _, _, task = prepare_remediation()

    response = client.get(
        f"/api/v1/remediations/{task['id']}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["id"] == task["id"]


def test_missing_remediation_returns_404():
    headers = register_and_login()

    response = client.get(
        "/api/v1/remediations/99999999",
        headers=headers,
    )
    assert response.status_code == 404


def test_update_remediation():
    headers, _, _, _, task = prepare_remediation()

    response = client.patch(
        f"/api/v1/remediations/{task['id']}",
        headers=headers,
        json={"title": "Updated remediation task title"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["title"] == "Updated remediation task title"


def test_start_remediation():
    _, analyst_headers, _, _, task = prepare_remediation()

    response = client.post(
        f"/api/v1/remediations/{task['id']}/start",
        headers=analyst_headers,
        json={"details": "Starting remediation work."},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "IN_PROGRESS"


def test_cannot_add_evidence_before_start():
    _, analyst_headers, _, _, task = prepare_remediation()

    response = client.post(
        f"/api/v1/remediations/{task['id']}/evidence",
        headers=analyst_headers,
        json={
            "evidence_type": "NOTE",
            "description": "Patch verification evidence",
        },
    )
    assert response.status_code == 409


def test_add_evidence_and_list_it():
    _, analyst_headers, _, _, task = prepare_remediation()

    start_response = client.post(
        f"/api/v1/remediations/{task['id']}/start",
        headers=analyst_headers,
        json={"details": "Starting remediation work."},
    )
    assert start_response.status_code == 200, start_response.text

    evidence_response = client.post(
        f"/api/v1/remediations/{task['id']}/evidence",
        headers=analyst_headers,
        json={
            "evidence_type": "NOTE",
            "description": "Security patch applied successfully.",
        },
    )
    assert evidence_response.status_code == 201, evidence_response.text

    list_response = client.get(
        f"/api/v1/remediations/{task['id']}/evidence",
        headers=analyst_headers,
    )
    assert list_response.status_code == 200, list_response.text
    assert len(list_response.json()) >= 1


def test_url_evidence_requires_url():
    _, analyst_headers, _, _, task = prepare_remediation()

    client.post(
        f"/api/v1/remediations/{task['id']}/start",
        headers=analyst_headers,
        json={"details": "Starting remediation work."},
    )

    response = client.post(
        f"/api/v1/remediations/{task['id']}/evidence",
        headers=analyst_headers,
        json={
            "evidence_type": "URL",
            "description": "Patch verification report",
        },
    )
    assert response.status_code == 422, response.text


def test_submit_requires_evidence():
    _, analyst_headers, _, _, task = prepare_remediation()

    client.post(
        f"/api/v1/remediations/{task['id']}/start",
        headers=analyst_headers,
        json={"details": "Starting remediation work."},
    )

    response = client.post(
        f"/api/v1/remediations/{task['id']}/submit",
        headers=analyst_headers,
        json={"details": "Submitting completed remediation."},
    )
    assert response.status_code == 422, response.text



def test_complete_approval_workflow():
    _, analyst_headers, _, _, task = prepare_remediation()
    task_id = task["id"]

    reviewer_headers = register_and_login("SECURITY_MANAGER")

    response = client.post(
        f"/api/v1/remediations/{task_id}/start",
        headers=analyst_headers,
        json={"details": "Starting remediation."},
    )
    assert response.status_code == 200, response.text

    response = client.post(
        f"/api/v1/remediations/{task_id}/evidence",
        headers=analyst_headers,
        json={
            "evidence_type": "NOTE",
            "description": "Patch installed and validated.",
        },
    )
    assert response.status_code == 201, response.text

    response = client.post(
        f"/api/v1/remediations/{task_id}/submit",
        headers=analyst_headers,
        json={"details": "Submitting patch evidence for review."},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "PENDING_APPROVAL"

    response = client.post(
        f"/api/v1/remediations/{task_id}/review",
        headers=reviewer_headers,
        json={
            "decision": "APPROVE",
            "comment": "Evidence verified; remediation approved.",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "COMPLETED"

def test_creator_cannot_approve_own_remediation():
    manager_headers, analyst_headers, _, _, task = prepare_remediation()
    task_id = task["id"]

    client.post(
        f"/api/v1/remediations/{task_id}/start",
        headers=analyst_headers,
        json={"details": "Starting remediation."},
    )
    client.post(
        f"/api/v1/remediations/{task_id}/evidence",
        headers=analyst_headers,
        json={
            "evidence_type": "NOTE",
            "description": "Patch applied.",
        },
    )
    client.post(
        f"/api/v1/remediations/{task_id}/submit",
        headers=analyst_headers,
        json={"details": "Requesting approval."},
    )

    response = client.post(
        f"/api/v1/remediations/{task_id}/review",
        headers=manager_headers,
        json={
            "decision": "APPROVE",
            "comment": "Attempting to approve own task.",
        },
    )

    # The manager created this task, so self-approval must be rejected.
    assert response.status_code == 403


def test_reject_remediation():
    manager_headers, analyst_headers, _, _, task = prepare_remediation()
    task_id = task["id"]

    client.post(
        f"/api/v1/remediations/{task_id}/start",
        headers=analyst_headers,
        json={"details": "Starting remediation."},
    )
    client.post(
        f"/api/v1/remediations/{task_id}/evidence",
        headers=analyst_headers,
        json={
            "evidence_type": "NOTE",
            "description": "Initial patch evidence.",
        },
    )
    client.post(
        f"/api/v1/remediations/{task_id}/submit",
        headers=analyst_headers,
        json={"details": "Submitting for review."},
    )

    reviewer_headers = register_and_login("SECURITY_MANAGER")
    response = client.post(
        f"/api/v1/remediations/{task_id}/review",
        headers=reviewer_headers,
        json={
            "decision": "REJECT",
            "comment": "Additional verification is required.",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "REJECTED"


def test_cancel_remediation():
    headers, _, _, _, task = prepare_remediation()

    response = client.post(
        f"/api/v1/remediations/{task['id']}/cancel",
        headers=headers,
        json={"reason": "Cancelled for integration testing."},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "CANCELLED"


def test_history_contains_task_creation():
    headers, _, _, _, task = prepare_remediation()

    response = client.get(
        f"/api/v1/remediations/{task['id']}/history",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert any(item["action"] == "CREATED" for item in response.json())


def test_history_missing_task_returns_404():
    headers = register_and_login()

    response = client.get(
        "/api/v1/remediations/99999999/history",
        headers=headers,
    )
    assert response.status_code == 404


def test_cancelled_task_cannot_be_cancelled_again():
    headers, _, _, _, task = prepare_remediation()
    task_id = task["id"]

    response = client.post(
        f"/api/v1/remediations/{task_id}/cancel",
        headers=headers,
        json={"reason": "Cancel this test task."},
    )
    assert response.status_code == 200, response.text

    response = client.post(
        f"/api/v1/remediations/{task_id}/cancel",
        headers=headers,
        json={"reason": "Attempt to cancel again."},
    )
    assert response.status_code == 409
