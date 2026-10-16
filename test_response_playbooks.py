
import os
import uuid

os.environ["ENVIRONMENT"] = "development"
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:Srik8499@localhost:5433/cybersecurity_incident_threat_test",
)

from fastapi.testclient import TestClient
from sqlalchemy import select

from main import app
from database import SessionLocal
from models.user import User
from models.incident import Incident
from models.investigation import Investigation
from models.alert import Alert

client = TestClient(app)

BASE_URL = "/api/v1/response-playbooks"

MANAGER_ROLES = {"SUPER_ADMIN", "SECURITY_MANAGER"}
EDITOR_ROLES = MANAGER_ROLES | {"SECURITY_ANALYST"}
RESPONDER_ROLES = EDITOR_ROLES | {"INCIDENT_RESPONDER"}


def unique_email():
    return f"playbook_{uuid.uuid4().hex[:12]}@example.com"


def create_user(role="SECURITY_ANALYST"):
    email = unique_email()
    password = "TestPassword123!"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": f"Playbook {role}",
            "email": email,
            "password": password,
        },
    )
    assert response.status_code in (200, 201), response.text

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        assert user is not None
        user.role = role
        user.is_active = True
        db.commit()
        user_id = user.id

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text

    token = response.json().get("access_token")
    assert token

    return {
        "id": user_id,
        "email": email,
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
        "role": role,
    }



def create_incident(user):
    suffix = uuid.uuid4().hex[:8]

    # Create a valid alert first, because the incident API requires alert_id.
    with SessionLocal() as db:
        alert = Alert(
            external_alert_id=f"PB-TEST-{suffix}",
            source="INTEGRATION_TEST",
            title=f"Playbook test alert {suffix}",
            description="Simulated security alert for playbook tests",
            category="OTHER",
            severity="HIGH",
            status="NEW",
            created_by=user["id"],
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_id = alert.id

    # The incident API requires alert_id and a supported category.
    response = client.post(
        "/api/v1/incidents",
        json={
            "alert_id": alert_id,
            "title": f"Playbook test incident {suffix}",
            "description": (
                "Simulated incident for response playbook integration tests"
            ),
            "category": "OTHER",
            "severity": "HIGH",
        },
        headers=user["headers"],
    )

    assert response.status_code in (200, 201), (
        f"Could not create test incident: "
        f"{response.status_code} {response.text}"
    )

    return response.json()["id"]


def create_investigation(user, incident_id):
    suffix = uuid.uuid4().hex[:8]

    response = client.post(
        "/api/v1/investigations",
        json={
            "title": f"Playbook investigation {suffix}",
            "description": "Investigation created for playbook integration tests",
            "priority": "HIGH",
            "incident_id": incident_id,
        },
        headers=user["headers"],
    )

    if response.status_code in (200, 201):
        return response.json()["id"]

    with SessionLocal() as db:
        investigation = db.scalar(select(Investigation))
        if investigation is not None:
            return investigation.id

    raise AssertionError(
        f"Could not create investigation: "
        f"{response.status_code} {response.text}"
    )


def create_playbook(user, requires_approval=False):
    suffix = uuid.uuid4().hex[:8]

    response = client.post(
        BASE_URL,
        json={
            "name": f"Test Response Playbook {suffix}",
            "description": "Integration test playbook with simulated steps",
            "category": "INCIDENT_RESPONSE",
            "severity": "HIGH",
            "steps": [
                {
                    "step_number": 1,
                    "title": "Review incident evidence",
                    "description": "Review available evidence references",
                    "step_type": "INVESTIGATION",
                    "requires_approval": False,
                },
                {
                    "step_number": 2,
                    "title": "Approve simulated containment",
                    "description": "Record approval for a simulated action only",
                    "step_type": "SIMULATED_ACTION",
                    "requires_approval": requires_approval,
                },
            ],
        },
        headers=user["headers"],
    )

    assert response.status_code == 201, response.text
    return response.json()


def start_execution(user, playbook_id, incident_id):
    response = client.post(
        f"{BASE_URL}/{playbook_id}/executions",
        json={"incident_id": incident_id, "summary": "Test execution"},
        headers=user["headers"],
    )
    assert response.status_code == 201, response.text
    return response.json()


def get_execution_steps(user, execution_id):
    response = client.get(
        f"{BASE_URL}/executions/{execution_id}/steps",
        headers=user["headers"],
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_create_playbook_success():
    user = create_user("SECURITY_ANALYST")

    playbook = create_playbook(user)

    assert playbook["id"] > 0
    assert playbook["name"].startswith("Test Response Playbook")
    assert playbook["is_active"] is True


def test_create_playbook_requires_authentication():
    response = client.post(
        BASE_URL,
        json={
            "name": "Unauthenticated playbook",
            "category": "GENERAL",
            "severity": "MEDIUM",
            "steps": [
                {
                    "step_number": 1,
                    "title": "Review evidence",
                    "step_type": "INVESTIGATION",
                }
            ],
        },
    )

    assert response.status_code in (401, 403)


def test_viewer_cannot_create_playbook():
    viewer = create_user("VIEWER")

    response = client.post(
        BASE_URL,
        json={
            "name": "Viewer playbook",
            "category": "GENERAL",
            "severity": "MEDIUM",
            "steps": [
                {
                    "step_number": 1,
                    "title": "Review evidence",
                    "step_type": "INVESTIGATION",
                }
            ],
        },
        headers=viewer["headers"],
    )

    assert response.status_code == 403


def test_duplicate_step_numbers_are_rejected():
    user = create_user("SECURITY_ANALYST")

    response = client.post(
        BASE_URL,
        json={
            "name": "Duplicate step numbers",
            "category": "GENERAL",
            "severity": "MEDIUM",
            "steps": [
                {"step_number": 1, "title": "First step"},
                {"step_number": 1, "title": "Second step"},
            ],
        },
        headers=user["headers"],
    )

    assert response.status_code == 422


def test_list_playbooks():
    user = create_user("SECURITY_ANALYST")
    playbook = create_playbook(user)

    response = client.get(BASE_URL, headers=user["headers"])

    assert response.status_code == 200, response.text
    assert any(item["id"] == playbook["id"] for item in response.json())


def test_viewer_can_read_playbooks():
    manager = create_user("SECURITY_MANAGER")
    viewer = create_user("VIEWER")
    playbook = create_playbook(manager)

    response = client.get(
        f"{BASE_URL}/{playbook['id']}",
        headers=viewer["headers"],
    )

    assert response.status_code == 200, response.text
    assert response.json()["id"] == playbook["id"]


def test_list_playbook_steps_in_order():
    user = create_user("SECURITY_ANALYST")
    playbook = create_playbook(user)

    response = client.get(
        f"{BASE_URL}/{playbook['id']}/steps",
        headers=user["headers"],
    )

    assert response.status_code == 200, response.text
    numbers = [step["step_number"] for step in response.json()]
    assert numbers == sorted(numbers)
    assert len(numbers) == 2


def test_start_execution_requires_related_record():
    user = create_user("SECURITY_ANALYST")
    playbook = create_playbook(user)

    response = client.post(
        f"{BASE_URL}/{playbook['id']}/executions",
        json={"summary": "Missing incident and investigation"},
        headers=user["headers"],
    )

    assert response.status_code == 422


def test_start_execution_success():
    user = create_user("SECURITY_ANALYST")
    incident_id = create_incident(user)
    playbook = create_playbook(user)

    execution = start_execution(user, playbook["id"], incident_id)

    assert execution["id"] > 0
    assert execution["playbook_id"] == playbook["id"]
    assert execution["incident_id"] == incident_id
    assert execution["status"] == "IN_PROGRESS"

    steps = get_execution_steps(user, execution["id"])
    assert len(steps) == 2
    assert [step["step_number"] for step in steps] == [1, 2]


def test_viewer_cannot_start_execution():
    manager = create_user("SECURITY_MANAGER")
    viewer = create_user("VIEWER")
    incident_id = create_incident(manager)
    playbook = create_playbook(manager)

    response = client.post(
        f"{BASE_URL}/{playbook['id']}/executions",
        json={"incident_id": incident_id},
        headers=viewer["headers"],
    )

    assert response.status_code == 403


def test_sensitive_step_cannot_complete_without_approval():
    user = create_user("SECURITY_ANALYST")
    incident_id = create_incident(user)
    playbook = create_playbook(user, requires_approval=True)
    execution = start_execution(user, playbook["id"], incident_id)
    steps = get_execution_steps(user, execution["id"])

    sensitive_step = next(
        step for step in steps if step["requires_approval"]
    )

    response = client.patch(
        f"{BASE_URL}/executions/{execution['id']}/steps/{sensitive_step['id']}",
        json={
            "status": "COMPLETED",
            "completion_notes": "Simulated action complete",
        },
        headers=user["headers"],
    )

    assert response.status_code == 403


def test_viewer_cannot_approve_sensitive_step():
    manager = create_user("SECURITY_MANAGER")
    viewer = create_user("VIEWER")
    incident_id = create_incident(manager)
    playbook = create_playbook(manager, requires_approval=True)
    execution = start_execution(manager, playbook["id"], incident_id)
    steps = get_execution_steps(manager, execution["id"])
    sensitive_step = next(
        step for step in steps if step["requires_approval"]
    )

    response = client.post(
        f"{BASE_URL}/executions/{execution['id']}/steps/{sensitive_step['id']}/approval",
        json={"decision": "APPROVED", "notes": "Test approval"},
        headers=viewer["headers"],
    )

    assert response.status_code == 403


def test_manager_can_approve_sensitive_step():
    manager = create_user("SECURITY_MANAGER")
    incident_id = create_incident(manager)
    playbook = create_playbook(manager, requires_approval=True)
    execution = start_execution(manager, playbook["id"], incident_id)
    steps = get_execution_steps(manager, execution["id"])
    sensitive_step = next(
        step for step in steps if step["requires_approval"]
    )

    response = client.post(
        f"{BASE_URL}/executions/{execution['id']}/steps/{sensitive_step['id']}/approval",
        json={"decision": "APPROVED", "notes": "Approved for simulation"},
        headers=manager["headers"],
    )

    assert response.status_code == 200, response.text
    assert response.json()["approval_status"] == "APPROVED"


def test_execution_step_completion_and_history():
    user = create_user("SECURITY_ANALYST")
    incident_id = create_incident(user)
    playbook = create_playbook(user)
    execution = start_execution(user, playbook["id"], incident_id)
    steps = get_execution_steps(user, execution["id"])

    first_step = steps[0]

    response = client.patch(
        f"{BASE_URL}/executions/{execution['id']}/steps/{first_step['id']}",
        json={
            "status": "COMPLETED",
            "completion_notes": "Reviewed evidence references",
        },
        headers=user["headers"],
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "COMPLETED"

    history_response = client.get(
        f"{BASE_URL}/executions/{execution['id']}/history",
        headers=user["headers"],
    )

    assert history_response.status_code == 200, history_response.text
    actions = [item["action"] for item in history_response.json()]
    assert "EXECUTION_STARTED" in actions
    assert "STEP_COMPLETED" in actions


def test_execution_completes_when_all_steps_are_finished():
    user = create_user("SECURITY_ANALYST")
    incident_id = create_incident(user)
    playbook = create_playbook(user)
    execution = start_execution(user, playbook["id"], incident_id)
    steps = get_execution_steps(user, execution["id"])

    for step in steps:
        response = client.patch(
            f"{BASE_URL}/executions/{execution['id']}/steps/{step['id']}",
            json={
                "status": "COMPLETED",
                "completion_notes": "Completed in simulation",
            },
            headers=user["headers"],
        )
        assert response.status_code == 200, response.text

    response = client.get(
        f"{BASE_URL}/executions/{execution['id']}",
        headers=user["headers"],
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "COMPLETED"
    assert response.json()["completed_at"] is not None


def test_execution_cannot_be_modified_after_completion():
    user = create_user("SECURITY_ANALYST")
    incident_id = create_incident(user)
    playbook = create_playbook(user)
    execution = start_execution(user, playbook["id"], incident_id)
    steps = get_execution_steps(user, execution["id"])

    for step in steps:
        response = client.patch(
            f"{BASE_URL}/executions/{execution['id']}/steps/{step['id']}",
            json={"status": "SKIPPED", "completion_notes": "Test skip"},
            headers=user["headers"],
        )
        assert response.status_code == 200, response.text

    response = client.patch(
        f"{BASE_URL}/executions/{execution['id']}/steps/{steps[0]['id']}",
        json={"status": "IN_PROGRESS"},
        headers=user["headers"],
    )

    assert response.status_code == 409
