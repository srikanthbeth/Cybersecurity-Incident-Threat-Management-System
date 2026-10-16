import os
from uuid import uuid4

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:Srik8499@localhost:5433/cybersecurity_incident_threat_test",
)
os.environ.setdefault("ENVIRONMENT", "development")

from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def register_and_login():
    email = f"report-test-{uuid4().hex[:10]}@example.com"
    password = "StrongPassword123!"

    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Report Test User",
            "email": email,
            "password": password,
        },
    )

    assert register_response.status_code in (200, 201), register_response.text

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_reports_require_authentication():
    response = client.get("/api/v1/reports/daily-incidents")
    assert response.status_code in (401, 403)


def test_daily_incident_report_returns_json():
    headers = register_and_login()

    response = client.get(
        "/api/v1/reports/daily-incidents",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    body = response.json()
    assert body["report"] == "daily_incident_summary"
    assert "total_incidents" in body
    assert "items" in body


def test_weekly_security_report_returns_json():
    headers = register_and_login()

    response = client.get(
        "/api/v1/reports/weekly-security",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["report"] == "weekly_security_summary"


def test_vulnerability_analysis_returns_json():
    headers = register_and_login()

    response = client.get(
        "/api/v1/reports/vulnerability-analysis",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["report"] == "vulnerability_analysis"


def test_sla_report_does_not_invent_compliance():
    headers = register_and_login()

    response = client.get(
        "/api/v1/reports/sla-compliance",
        headers=headers,
    )

    assert response.status_code == 403, response.text


def test_csv_export_returns_csv():
    headers = register_and_login()

    response = client.get(
        "/api/v1/reports/csv/daily-incidents",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert "text/csv" in response.headers["content-type"]
    assert ".csv" in response.headers["content-disposition"]


def test_invalid_report_date_range_returns_422():
    headers = register_and_login()

    response = client.get(
        "/api/v1/reports/daily-incidents",
        params={
            "start_date": "2026-10-15",
            "end_date": "2026-10-01",
        },
        headers=headers,
    )

    assert response.status_code == 422, response.text


def test_unknown_report_returns_404():
    headers = register_and_login()

    response = client.get(
        "/api/v1/reports/not-a-real-report",
        headers=headers,
    )

    assert response.status_code == 404, response.text
