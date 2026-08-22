import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_scan_and_history_workflow():
    # Fetch initial history count
    initial_resp = client.get("/api/v1/history")
    assert initial_resp.status_code == 200
    initial_data = initial_resp.json()
    initial_total = initial_data["total_scans"]
    print("INITIAL SCANS:", initial_total)

    # Perform URL scan
    url_resp = client.post(
        "/api/v1/scan/url",
        json={"url": "https://example-test-history.com"}
    )
    assert url_resp.status_code == 200

    # Perform Message scan
    msg_resp = client.post(
        "/api/v1/scan/message",
        json={"message": "URGENT: Verify your credentials at http://test-phish.xyz immediately!"}
    )
    assert msg_resp.status_code == 200

    # Retrieve history
    history_resp = client.get("/api/v1/history")
    assert history_resp.status_code == 200
    data = history_resp.json()
    print("FINAL SCANS:", data["total_scans"])
    print("SCANS IN RESPONSE:", [(s["id"], s["target"]) for s in data["scans"]])

    assert "total_scans" in data
    assert "risk_breakdown" in data
    assert "scans" in data

    assert data["total_scans"] == initial_total + 2
    assert len(data["scans"]) <= 20
    assert len(data["scans"]) >= 2

    # Check risk breakdown keys
    breakdown = data["risk_breakdown"]
    assert "high" in breakdown
    assert "medium" in breakdown
    assert "low" in breakdown

    # Check recent scan entries
    recent_targets = [s["target"] for s in data["scans"]]
    assert "https://example-test-history.com" in recent_targets
    assert "URGENT: Verify your credentials at http://test-phish.xyz immediately!" in recent_targets

