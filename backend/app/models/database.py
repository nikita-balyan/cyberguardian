from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./cyberguardian.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class ScanAuditLog(Base):
    __tablename__ = "scan_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True)  # "url" | "qr" | "message"
    target = Column(Text)
    risk_level = Column(String, index=True)
    risk_score = Column(Integer)
    summary = Column(Text)
    evidence = Column(JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def init_db():
    Base.metadata.create_all(bind=engine)


# Auto-create tables on import
init_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


