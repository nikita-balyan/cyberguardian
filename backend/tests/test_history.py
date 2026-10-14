#test_history.py
import uuid

import pytest
from fastapi.testclient import TestClient

from app import security
from app.main import app
from app.models.database import ScanAuditLog, SessionLocal

client = TestClient(app)


def new_visitor() -> str:
    return str(uuid.uuid4())


def hdr(visitor_id: str) -> dict:
    return {"X-Visitor-Id": visitor_id}


def add_scan(owner_id, target, level="LOW", score=5):
    """Insert a history row directly, so these tests need no network."""
    db = SessionLocal()
    try:
        db.add(ScanAuditLog(
            owner_id=owner_id,
            modality="url",
            target=target,
            severity_level=level,
            composite_risk_score=score,
            heuristic_score=float(score),
            ml_probability=0.0,
            evidence_json={},
        ))
        db.commit()
    finally:
        db.close()


def test_scan_and_history_workflow():
    visitor = new_visitor()

    initial = client.get("/api/v1/history", headers=hdr(visitor))
    assert initial.status_code == 200
    assert initial.json()["total_scans"] == 0

    url_resp = client.post(
        "/api/v1/scan/url",
        json={"url": "https://example-test-history.com"},
        headers=hdr(visitor),
    )
    assert url_resp.status_code == 200

    msg_resp = client.post(
        "/api/v1/scan/message",
        json={"message": "URGENT: Verify your credentials at http://test-phish.xyz immediately!"},
        headers=hdr(visitor),
    )
    assert msg_resp.status_code == 200

    history_resp = client.get("/api/v1/history", headers=hdr(visitor))
    assert history_resp.status_code == 200
    data = history_resp.json()

    assert "total_scans" in data
    assert "risk_breakdown" in data
    assert "scans" in data
    assert data["total_scans"] == 2
    assert 2 <= len(data["scans"]) <= 50

    breakdown = data["risk_breakdown"]
    assert "high" in breakdown
    assert "medium" in breakdown
    assert "low" in breakdown

    recent_targets = [s["target"] for s in data["scans"]]
    assert "https://example-test-history.com" in recent_targets
    assert "URGENT: Verify your credentials at http://test-phish.xyz immediately!" in recent_targets


def test_history_is_private_between_visitors():
    alice, bob = new_visitor(), new_visitor()
    add_scan(alice, "https://alice-only.example")

    alice_view = client.get("/api/v1/history", headers=hdr(alice)).json()
    bob_view = client.get("/api/v1/history", headers=hdr(bob)).json()

    assert alice_view["total_scans"] == 1
    assert [s["target"] for s in alice_view["scans"]] == ["https://alice-only.example"]
    assert bob_view["total_scans"] == 0
    assert bob_view["scans"] == []


def test_history_without_a_valid_visitor_id_is_empty():
    add_scan(new_visitor(), "https://someone-elses-scan.example")

    for headers in ({}, {"X-Visitor-Id": "not-a-uuid"}):
        data = client.get("/api/v1/history", headers=headers).json()
        assert data["total_scans"] == 0
        assert data["scans"] == []


def test_risk_breakdown_counts_only_own_scans():
    me, other = new_visitor(), new_visitor()
    add_scan(me, "https://a.example", level="LOW", score=5)
    add_scan(me, "https://b.example", level="HIGH", score=70)
    add_scan(me, "https://c.example", level="CRITICAL", score=95)
    add_scan(other, "https://d.example", level="HIGH", score=70)

    data = client.get("/api/v1/history", headers=hdr(me)).json()
    assert data["total_scans"] == 3
    assert data["risk_breakdown"]["low"] == 1
    assert data["risk_breakdown"]["critical"] == 1
    assert data["risk_breakdown"]["high"] == 2  # "high" means high + critical


def test_delete_history_removes_only_own_scans():
    a, b = new_visitor(), new_visitor()
    add_scan(a, "https://a1.example")
    add_scan(a, "https://a2.example")
    add_scan(b, "https://b1.example")

    resp = client.delete("/api/v1/history", headers=hdr(a))
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2

    assert client.get("/api/v1/history", headers=hdr(a)).json()["total_scans"] == 0
    assert client.get("/api/v1/history", headers=hdr(b)).json()["total_scans"] == 1


def test_delete_history_requires_a_visitor_id():
    assert client.delete("/api/v1/history").status_code == 400


def test_scan_rate_limit_returns_429():
    limit = security.scan_limiter.limit
    if limit <= 0:
        pytest.skip("scan rate limit is disabled")
    too_long = "http://" + "a" * 3000  # rejected with 400 before any network work, but still counted

    for _ in range(limit):
        assert client.post("/api/v1/scan/url", json={"url": too_long}).status_code == 400

    resp = client.post("/api/v1/scan/url", json={"url": too_long})
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_batch_rate_limit_returns_429():
    limit = security.batch_limiter.limit
    if limit <= 0:
        pytest.skip("batch rate limit is disabled")
    bad_batch = {"items": ["x"], "scan_type": "bogus"}  # rejected with 400, but still counted

    for _ in range(limit):
        assert client.post("/api/v1/scan/batch", json=bad_batch).status_code == 400

    assert client.post("/api/v1/scan/batch", json=bad_batch).status_code == 429


def test_read_rate_limit_returns_429():
    limit = security.read_limiter.limit
    if limit <= 0:
        pytest.skip("read rate limit is disabled")

    for _ in range(limit):
        assert client.get("/api/v1/history").status_code == 200

    assert client.get("/api/v1/history").status_code == 429
