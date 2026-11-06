from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

DATABASE_URL = "sqlite:///./secure_deploy.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class for SQLAlchemy ORM models."""


class ScanRecord(Base):
    """Database model representing a single security scan run."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, nullable=False)
    status = Column(String, nullable=False, default="queued")  # "queued", "running", "passed", "blocked", "failed"
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String, nullable=False, default="low")
    blocked_reason = Column(String, nullable=True)
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    findings = relationship(
        "FindingRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class FindingRecord(Base):
    """Database model representing a single secret finding linked to a scan."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    file = Column(String, nullable=False)
    line = Column(Integer, nullable=False)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    masked_preview = Column(String, nullable=False)

    scan = relationship("ScanRecord", back_populates="findings")


class DeploymentRecord(Base):
    """Database model representing a Docker container deployment."""

    __tablename__ = "deployments"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    project = Column(String, nullable=True, index=True)
    status = Column(String, nullable=False, default="pending")  # "pending", "building", "deploying", "probing", "deployed", "exposed", "failed", "stopped"
    image_tag = Column(String, nullable=False)
    container_name = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    url = Column(String, nullable=True)
    host_type = Column(String, nullable=False, default="local")  # "local" | "ec2"
    logs = Column(String, nullable=False, default="")  # Text max 20KB truncated
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    finished_at = Column(DateTime, nullable=True)

    scan = relationship("ScanRecord")
    probe_results = relationship(
        "ProbeResultRecord",
        back_populates="deployment",
        cascade="all, delete-orphan",
    )


class SecretMetadataRecord(Base):
    """Database model for secret metadata. Value is NEVER stored in the database."""

    __tablename__ = "secrets_metadata"

    id = Column(Integer, primary_key=True, index=True)
    project = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    backend = Column(String, nullable=False, default="local")
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class ProbeResultRecord(Base):
    """Database model representing individual post-deploy probe path verdicts."""

    __tablename__ = "probe_results"

    id = Column(Integer, primary_key=True, index=True)
    deployment_id = Column(Integer, ForeignKey("deployments.id", ondelete="CASCADE"), nullable=False, index=True)
    path = Column(String, nullable=False)
    status_code = Column(Integer, nullable=True)
    verdict = Column(String, nullable=False)  # "safe" | "exposed" | "warning"
    note = Column(String, nullable=True)
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    deployment = relationship("DeploymentRecord", back_populates="probe_results")


def allocate_next_port(db: Session, min_port: int = 9000, max_port: int = 9999) -> int:
    """Allocate an unused host port in the range 9000-9999 tracked in the DB."""
    # Find all ports currently occupied by active containers
    active_deployments = (
        db.query(DeploymentRecord.port)
        .filter(DeploymentRecord.status.in_(["pending", "building", "deploying", "probing", "deployed", "exposed"]))
        .filter(DeploymentRecord.port.isnot(None))
        .all()
    )
    used_ports = {row[0] for row in active_deployments}
    for candidate in range(min_port, max_port + 1):
        if candidate not in used_ports:
            return candidate
    raise RuntimeError("No available ports in range 9000-9999")


def init_db() -> None:
    """Create database tables if they do not exist and migrate columns if schema evolved."""
    Base.metadata.create_all(bind=engine)

    # Migrate existing SQLite database to include Day 2/3/5 columns if not present
    inspector = inspect(engine)
    if "scans" in inspector.get_table_names():
        columns = [col["name"] for col in inspector.get_columns("scans")]
        with engine.begin() as conn:
            if "risk_score" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN risk_score INTEGER DEFAULT 0"))
            if "risk_level" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN risk_level TEXT DEFAULT 'low'"))
            if "blocked_reason" not in columns:
                conn.execute(text("ALTER TABLE scans ADD COLUMN blocked_reason TEXT DEFAULT NULL"))

    if "deployments" in inspector.get_table_names():
        dep_columns = [col["name"] for col in inspector.get_columns("deployments")]
        with engine.begin() as conn:
            if "project" not in dep_columns:
                conn.execute(text("ALTER TABLE deployments ADD COLUMN project TEXT DEFAULT NULL"))


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy database session and close it when finished."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
