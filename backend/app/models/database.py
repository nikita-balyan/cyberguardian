#database.py
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import JSON, Index, create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID, JSONB
from sqlalchemy.orm import sessionmaker

from app.db.session import ASYNC_DATABASE_URL, async_engine, Base, async_session_maker

logger = logging.getLogger(__name__)

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberguardian.db")

# Normalize DB URL for the sync engine
if SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    _normalized_sync = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)
elif SQLALCHEMY_DATABASE_URL.startswith("postgresql+asyncpg://"):
    _normalized_sync = SQLALCHEMY_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
else:
    _normalized_sync = SQLALCHEMY_DATABASE_URL if SQLALCHEMY_DATABASE_URL else "sqlite:///./cyberguardian.db"

connect_args = {"check_same_thread": False} if _normalized_sync.startswith("sqlite") else {}

engine = create_engine(
    _normalized_sync,
    connect_args=connect_args,
    pool_pre_ping=True,   # drop dead connections (the Supabase pooler closes idle ones)
    pool_recycle=300,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class ScanAuditLog(Base):
    __tablename__ = "scan_audit_logs"
    __table_args__ = (Index("ix_scan_audit_logs_owner_created", "owner_id", "created_at"),)

    id = Column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4, index=True
    )
    # Anonymous per-browser id. NULL = old rows from before history was scoped (nobody can see them).
    owner_id = Column(String(64), nullable=True)
    target = Column(Text, nullable=False)
    modality = Column(String(20), nullable=False)  # "url" | "qr" | "text" | "batch"
    composite_risk_score = Column(Integer, nullable=False)
    severity_level = Column(String(20), nullable=False)  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    heuristic_score = Column(Float, nullable=False)
    ml_probability = Column(Float, nullable=False)
    intel_feed_hits = Column(Integer, default=0, nullable=False)
    evidence_json = Column(JSON().with_variant(JSONB, "postgresql"), nullable=False)
    ai_explanation = Column(Text, nullable=True)
    scan_duration_ms = Column(Integer, nullable=False, default=0)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Properties / aliases for backward compatibility with old code/tests
    @property
    def scan_type(self) -> str:
        return self.modality

    @scan_type.setter
    def scan_type(self, value: str):
        self.modality = value

    @property
    def risk_score(self) -> int:
        return self.composite_risk_score

    @risk_score.setter
    def risk_score(self, value: int):
        self.composite_risk_score = value

    @property
    def risk_level(self) -> str:
        return self.severity_level

    @risk_level.setter
    def risk_level(self, value: str):
        self.severity_level = value

    @property
    def summary(self) -> Optional[str]:
        return self.ai_explanation

    @summary.setter
    def summary(self, value: Optional[str]):
        self.ai_explanation = value

    @property
    def evidence(self) -> dict:
        return self.evidence_json

    @evidence.setter
    def evidence(self, value: dict):
        self.evidence_json = value


# Sync init. NOTE: create_all only creates MISSING tables. It never adds columns to an
# existing one, which is why the owner_id column needs the SQL in the setup steps.
def init_db() -> None:
    Base.metadata.create_all(bind=engine)


# Async init for Supabase
async def async_init_db() -> None:
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def purge_old_scans(retention_days: int) -> int:
    """Delete saved scans older than retention_days. Returns how many were removed."""
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    db = SessionLocal()
    try:
        removed = (
            db.query(ScanAuditLog)
            .filter(ScanAuditLog.created_at < cutoff)
            .delete(synchronize_session=False)
        )
        db.commit()
        return removed
    except Exception:
        db.rollback()
        logger.exception("Could not purge old scans")
        return 0
    finally:
        db.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
