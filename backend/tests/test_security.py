import pytest
from fastapi import HTTPException

from app.security import RateLimiter, get_owner_id

pytestmark = pytest.mark.skip_db_init


class FakeRequest:
    def __init__(self, ip="1.2.3.4"):
        self.headers = {}
        self.client = type("Client", (), {"host": ip})()


def make_limiter(limit=3, window=60, **kw):
    clock = {"t": 1000.0}
    limiter = RateLimiter("t", limit, window, "Too fast.", clock=lambda: clock["t"], **kw)
    return limiter, clock


def test_allows_up_to_the_limit_then_429_with_retry_after():
    limiter, _ = make_limiter(limit=3)
    req = FakeRequest()
    for _ in range(3):
        limiter.check(req)
    with pytest.raises(HTTPException) as exc:
        limiter.check(req)
    assert exc.value.status_code == 429
    assert "Retry-After" in exc.value.headers
    assert "Too fast." in exc.value.detail


def test_clients_are_counted_separately():
    limiter, _ = make_limiter(limit=1)
    limiter.check(FakeRequest("1.1.1.1"))
    limiter.check(FakeRequest("2.2.2.2"))  # a different IP is unaffected
    with pytest.raises(HTTPException):
        limiter.check(FakeRequest("1.1.1.1"))


def test_window_expires():
    limiter, clock = make_limiter(limit=1, window=60)
    req = FakeRequest()
    limiter.check(req)
    with pytest.raises(HTTPException):
        limiter.check(req)
    clock["t"] += 61
    limiter.check(req)  # allowed again


def test_cost_counts_against_the_limit():
    limiter, _ = make_limiter(limit=10, per_client=False)
    req = FakeRequest()
    limiter.check(req, cost=8)
    with pytest.raises(HTTPException):
        limiter.check(req, cost=5)


def test_zero_limit_disables_the_limiter():
    limiter, _ = make_limiter(limit=0)
    for _ in range(100):
        limiter.check(FakeRequest())


def test_owner_id_validation():
    good = "123e4567-e89b-42d3-a456-426614174000"
    assert get_owner_id(good.upper()) == good
    assert get_owner_id("not-a-uuid") is None
    assert get_owner_id("") is None
    assert get_owner_id(None) is None
    assert get_owner_id("x" * 40) is None