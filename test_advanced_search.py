
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
    email = f"search-{uuid4().hex[:12]}@example.com"
    password = "StrongPassword123!"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Advanced Search Tester",
            "email": email,
            "password": password,
        },
    )
    assert response.status_code in (200, 201), response.text

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text

    return {
        "Authorization": f"Bearer {response.json()['access_token']}"
    }


def test_advanced_search_requires_authentication():
    response = client.get("/api/v1/search/")
    assert response.status_code in (401, 403)


def test_advanced_search_returns_paginated_results():
    headers = register_and_login()

    response = client.get(
        "/api/v1/search/",
        params={"page": 1, "page_size": 10},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()

    assert "items" in body
    assert "pagination" in body
    assert body["pagination"]["page"] == 1
    assert body["pagination"]["page_size"] == 10
    assert body["pagination"]["total"] >= 0


def test_search_accepts_combined_filters():
    headers = register_and_login()

    response = client.get(
        "/api/v1/search/",
        params={
            "severity": "HIGH",
            "status": "INVESTIGATING",
            "page": 1,
            "page_size": 5,
            "sort_by": "created_at",
            "sort_order": "desc",
        },
        headers=headers,
    )

    assert response.status_code == 200, response.text

    for item in response.json()["items"]:
        assert item["severity"].upper() == "HIGH"
        assert item["status"].upper() == "INVESTIGATING"


def test_search_rejects_invalid_severity():
    headers = register_and_login()

    response = client.get(
        "/api/v1/search/",
        params={"severity": "EXTREME"},
        headers=headers,
    )

    assert response.status_code == 422, response.text


def test_search_rejects_invalid_date_range():
    headers = register_and_login()

    response = client.get(
        "/api/v1/search/",
        params={
            "start_date": "2026-10-15",
            "end_date": "2026-10-01",
        },
        headers=headers,
    )

    assert response.status_code == 422, response.text


def test_search_rejects_invalid_pagination():
    headers = register_and_login()

    response = client.get(
        "/api/v1/search/",
        params={"page": 0},
        headers=headers,
    )

    assert response.status_code == 422, response.text


def test_search_rejects_unsupported_sort_field():
    headers = register_and_login()

    response = client.get(
        "/api/v1/search/",
        params={"sort_by": "password_hash"},
        headers=headers,
    )

    assert response.status_code == 422, response.text


def test_incident_reference_search_requires_authentication():
    response = client.get(
        "/api/v1/search/incidents/reference/INC-2026"
    )

    assert response.status_code in (401, 403)


def test_incident_reference_search_returns_results_structure():
    headers = register_and_login()

    response = client.get(
        "/api/v1/search/incidents/reference/INC-2026",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()

    assert "items" in body
    assert "pagination" in body

    for item in body["items"]:
        assert item["record_type"] == "incident"
        assert "INC-2026".lower() in item["reference"].lower()
