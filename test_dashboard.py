
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://postgres:Srik8499@localhost:5433/"
    "cybersecurity_incident_threat_test"
)
os.environ["ENVIRONMENT"] = "development"

import pytest
from fastapi.testclient import TestClient

from core.security import hash_password
from database import Base, SessionLocal, engine
from main import app
from models.alert import Alert
from models.incident import Incident
from models.incident_history import IncidentHistory
from models.user import User


client = TestClient(app)

DASHBOARD_ENDPOINTS = [
    "/api/v1/dashboard/summary",
    "/api/v1/dashboard/vulnerabilities",
    "/api/v1/dashboard/analyst-workload",
    "/api/v1/dashboard/incident-trends",
    "/api/v1/dashboard/remediation",
]


# ---------------------------------------------------------
# SETUP AND HELPERS
# ---------------------------------------------------------

def setup_module():
    Base.metadata.create_all(bind=engine)


def unique_email():
    return f"dashboard_{uuid4().hex[:12]}@example.com"


def create_user(role="SECURITY_ANALYST"):
    email = unique_email()
    password = "DashboardTestPassword123!"

    db = SessionLocal()

    try:
        user = User(
            full_name="Dashboard Test Analyst",
            email=email,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        user_id = user.id

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

    return user_id, response.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------
# AUTHENTICATION TESTS
# ---------------------------------------------------------

@pytest.mark.parametrize("endpoint", DASHBOARD_ENDPOINTS)
def test_dashboard_endpoints_require_authentication(endpoint):
    response = client.get(endpoint)

    assert response.status_code == 401, response.text


# ---------------------------------------------------------
# DASHBOARD DATABASE METRIC TESTS
# ---------------------------------------------------------

def test_dashboard_metrics_use_real_database_records():
    user_id, token = create_user("SECURITY_ANALYST")
    headers = auth_headers(token)

    db = SessionLocal()
    incident_id = None
    alert_id = None

    try:
        # Read baseline metrics before inserting test records.
        baseline_response = client.get(
            "/api/v1/dashboard/summary",
            headers=headers,
        )

        assert baseline_response.status_code == 200, (
            baseline_response.text
        )

        baseline = baseline_response.json()

        now = datetime.now(timezone.utc)
        incident_number = f"DASH-{uuid4().hex[:12].upper()}"

        # Create a real incident assigned to this analyst.
        incident = Incident(
            incident_number=incident_number,
            title="Dashboard integration test incident",
            description="Test incident for dashboard metrics",
            category="MALWARE",
            severity="CRITICAL",
            status="NEW",
            assigned_to=user_id,
            created_by=user_id,
            created_at=now,
            updated_at=now,
        )

        db.add(incident)
        db.flush()

        incident_id = incident.id

        # A matching history action allows the dashboard to
        # calculate its documented response-time proxy.
        history = IncidentHistory(
            incident_id=incident.id,
            actor_id=user_id,
            action="INVESTIGATION_STARTED",
            old_value="NEW",
            new_value="INVESTIGATING",
            details="Dashboard integration test response",
            created_at=now + timedelta(seconds=30),
        )

        db.add(history)

        # Create a real critical alert.
        alert = Alert(
            external_alert_id=uuid4().hex,
            source="DASHBOARD_TEST",
            title="Dashboard critical alert",
            description="Test critical alert",
            category="MALWARE",
            severity="CRITICAL",
            status="NEW",
            created_by=user_id,
            detected_at=now,
            created_at=now,
            updated_at=now,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        alert_id = alert.id

        # SUMMARY
        response = client.get(
            "/api/v1/dashboard/summary",
            headers=headers,
        )

        assert response.status_code == 200, response.text
        summary = response.json()

        assert summary["total_incidents"] == (
            baseline["total_incidents"] + 1
        )
        assert summary["open_incidents"] == (
            baseline["open_incidents"] + 1
        )
        assert summary["critical_alerts"] == (
            baseline["critical_alerts"] + 1
        )

        assert summary["average_response_time_hours"] is not None
        assert summary["average_response_time_hours"] >= 0

        # SLA must not claim compliance without configured targets.
        assert summary["sla_compliance_percentage"] is None
        assert summary["sla_eligible_incidents"] == 0

        # VULNERABILITIES
        response = client.get(
            "/api/v1/dashboard/vulnerabilities",
            headers=headers,
        )

        assert response.status_code == 200, response.text
        vulnerability_data = response.json()

        assert "total" in vulnerability_data
        assert "by_severity" in vulnerability_data
        assert vulnerability_data["total"] == sum(
            vulnerability_data["by_severity"].values()
        )

        # ANALYST WORKLOAD
        response = client.get(
            "/api/v1/dashboard/analyst-workload",
            headers=headers,
        )

        assert response.status_code == 200, response.text
        workload = response.json()

        assert "items" in workload
        assert "total_analysts" in workload

        analyst = next(
            (
                item
                for item in workload["items"]
                if item["analyst_id"] == user_id
            ),
            None,
        )

        assert analyst is not None
        assert analyst["active_incidents"] >= 1
        assert analyst["total_active_work"] >= 1

        # INCIDENT TRENDS
        incident_date = now.date()

        response = client.get(
            "/api/v1/dashboard/incident-trends",
            params={
                "start_date": incident_date.isoformat(),
                "end_date": incident_date.isoformat(),
            },
            headers=headers,
        )

        assert response.status_code == 200, response.text
        trends = response.json()

        assert trends["start_date"] == incident_date.isoformat()
        assert trends["end_date"] == incident_date.isoformat()
        assert trends["total_incidents"] >= 1
        assert len(trends["items"]) == 1
        assert trends["items"][0]["count"] >= 1

        # REMEDIATION DASHBOARD
        response = client.get(
            "/api/v1/dashboard/remediation",
            headers=headers,
        )

        assert response.status_code == 200, response.text
        remediation = response.json()

        assert "total_tasks" in remediation
        assert "overdue_tasks" in remediation
        assert "overdue_by_priority" in remediation
        assert "overdue_by_status" in remediation

        assert remediation["total_tasks"] >= 0
        assert remediation["overdue_tasks"] >= 0

    
    finally:
        try:
            # Delete the test incident first. Its history is configured
            # to cascade when the incident is deleted.
            if incident_id is not None:
                incident = db.get(Incident, incident_id)
                if incident is not None:
                    db.delete(incident)
                    db.flush()

            # Delete the test alert.
            if alert_id is not None:
                alert = db.get(Alert, alert_id)
                if alert is not None:
                    db.delete(alert)
                    db.flush()

            # Delete the test user only after dependent records are gone.
            user = db.get(User, user_id)
            if user is not None:
                db.delete(user)

            db.commit()

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()



# ---------------------------------------------------------
# INCIDENT TREND VALIDATION TESTS
# ---------------------------------------------------------

def test_incident_trends_reject_reversed_date_range():
    _, token = create_user("SECURITY_ANALYST")

    today = datetime.now(timezone.utc).date()

    response = client.get(
        "/api/v1/dashboard/incident-trends",
        params={
            "start_date": (today + timedelta(days=1)).isoformat(),
            "end_date": today.isoformat(),
        },
        headers=auth_headers(token),
    )

    assert response.status_code == 422, response.text


def test_incident_trends_reject_range_over_366_days():
    _, token = create_user("SECURITY_ANALYST")

    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=366)

    response = client.get(
        "/api/v1/dashboard/incident-trends",
        params={
            "start_date": start_date.isoformat(),
            "end_date": today.isoformat(),
        },
        headers=auth_headers(token),
    )

    assert response.status_code == 422, response.text
