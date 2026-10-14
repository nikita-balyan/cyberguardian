#conftest.py
import os
import sys

# Always use a local SQLite test database, regardless of .env values.
# This MUST be set BEFORE any app imports that trigger dotenv loading.
os.environ["DATABASE_URL"] = "sqlite:///./cyberguardian.db"

# Add the project root so app imports work via pythonpath=backend in pytest.ini.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest


@pytest.fixture(scope="session", autouse=True)
def init_test_db(request):
    # Skip DB init for tests that don't need it (like ML tests)
    if request.node.get_closest_marker("skip_db_init"):
        yield
        return

    # For all other tests, initialize the database
    from app.models.database import init_db, engine, SessionLocal, ScanAuditLog
    # Drop existing tables so the schema is re-created on every test run.
    ScanAuditLog.__table__.drop(bind=engine, checkfirst=True)
    init_db()
    yield
    ScanAuditLog.__table__.drop(bind=engine, checkfirst=True)


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Rate-limit counters live in memory. Clear them so tests never affect each other."""
    from app import security
    for limiter in (security.scan_limiter, security.batch_limiter,
                    security.read_limiter, security.daily_cap):
        limiter._hits.clear()
    yield


@pytest.fixture
def db_session():
    from app.models.database import SessionLocal
    yield SessionLocal()