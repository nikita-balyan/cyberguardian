import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_benign_text_message():
    response = client.post(
        "/api/v1/scan/message",
        json={"message": "Hey, let's meet up for coffee tomorrow afternoon."}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Hey, let's meet up for coffee tomorrow afternoon."
    assert "evidence" in data
    assert "risk_assessment" in data
    assert "explanation" in data
    assert data["risk_assessment"]["level"] == "LOW"


def test_urgency_triggers():
    response = client.post(
        "/api/v1/scan/message",
        json={"message": "URGENT: Your account has been suspended! Act immediately to prevent permanent deactivation."}
    )
    assert response.status_code == 200
    data = response.json()
    assert "evidence" in data
    assert data["risk_assessment"]["score"] > 0


def test_financial_lure_and_url():
    response = client.post(
        "/api/v1/scan/message",
        json={"message": "Congratulations! Claim your $1,000 cash refund now: http://claim-funds-now.top"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "evidence" in data
    assert "risk_assessment" in data
    assert "explanation" in data


def test_empty_message_validation():
    response = client.post(
        "/api/v1/scan/message",
        json={"message": ""}
    )
    # Fast validation handles empty strings gracefully
    assert response.status_code in [200, 422]