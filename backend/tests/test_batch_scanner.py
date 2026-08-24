import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_batch_scan_urls():
    response = client.post(
        "/api/v1/scan/batch",
        json={
            "scan_type": "url",
            "items": [
                "https://example.com",
                "http://malicious-sbi-login.xyz",
                "https://google.com"
            ]
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_items"] == 3
    assert "high_risk_count" in data
    assert "medium_risk_count" in data
    assert "low_risk_count" in data
    assert len(data["results"]) == 3
    # Check that results are sorted by risk score descending
    scores = [r["risk_score"] for r in data["results"]]
    assert scores == sorted(scores, reverse=True)

def test_batch_scan_messages():
    response = client.post(
        "/api/v1/scan/batch",
        json={
            "scan_type": "message",
            "items": [
                "Hello, how are you doing today?",
                "URGENT: Your bank account is locked! Click http://phish-bank.com immediately to verify."
            ]
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_items"] == 2
    assert len(data["results"]) == 2
    assert data["results"][0]["risk_score"] >= data["results"][1]["risk_score"]

def test_batch_scan_limit_exceeded():
    items = [f"https://example{i}.com" for i in range(51)]
    response = client.post(
        "/api/v1/scan/batch",
        json={
            "scan_type": "url",
            "items": items
        }
    )
    assert response.status_code == 400
    assert "Maximum 50 items allowed" in response.json()["detail"]

def test_batch_scan_empty():
    response = client.post(
        "/api/v1/scan/batch",
        json={
            "scan_type": "url",
            "items": []
        }
    )
    assert response.status_code == 400
    assert "No valid items provided" in response.json()["detail"]
