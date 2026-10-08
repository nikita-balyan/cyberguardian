import os
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import JSON, create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID, JSONB
from sqlalchemy.orm import declarative_base, sessionmaker

from app.db.session import ASYNC_DATABASE_URL, async_engine, Base, async_session_maker

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberguardian.db")

# Normalize DB URL for sync engine (ensure postgresql:// and omit SQLite-specific connect_args for PostgreSQL)
if SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    _normalized_sync = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)
elif SQLALCHEMY_DATABASE_URL.startswith("postgresql+asyncpg://"):
    _normalized_sync = SQLALCHEMY_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
else:
    _normalized_sync = SQLALCHEMY_DATABASE_URL if SQLALCHEMY_DATABASE_URL else "sqlite:///./cyberguardian.db"

connect_args = {"check_same_thread": False} if _normalized_sync.startswith("sqlite") else {}

engine = create_engine(
    _normalized_sync, connect_args=connect_args
)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class ScanAuditLog(Base):
    __tablename__ = "scan_audit_logs"

    id = Column(
        PostgreSQLUUID(as_uuid=True), primary_key=True, default=uuid4, index=True
    )
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



# Keep backward compatibility init_db for sync engine
def init_db() -> None:
    Base.metadata.create_all(bind=engine)


# Async init for Supabase
async def async_init_db() -> None:
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


