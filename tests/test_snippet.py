from __future__ import annotations

import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.scans import reset_rate_limits
from db import Base, ScanRecord, get_db
from main import app


@pytest.fixture(autouse=True)
def clean_rate_limits():
    reset_rate_limits()


@pytest.fixture
def client_and_db():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    db = TestingSessionLocal()
    try:
        yield client, db
    finally:
        db.close()
        app.dependency_overrides.clear()


def test_snippet_detects_fake_aws_key_with_masked_preview(client_and_db):
    """Verify snippet scanner flags AKIAIOSFODNN7EXAMPLE and returns masked preview."""
    client, _ = client_and_db
    payload = {
        "content": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
        "filename": "creds.py",
    }
    resp = client.post("/api/scans/snippet", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "blocked"
    assert data["risk_score"] > 0
    assert len(data["findings"]) >= 1

    aws_finding = next((f for f in data["findings"] if f["type"] == "aws_access_key"), None)
    assert aws_finding is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_finding["masked_preview"]
    assert "AKIA" in aws_finding["masked_preview"]
    assert aws_finding["file"] == "creds.py"


def test_snippet_clean_code_passes(client_and_db):
    """Verify clean snippet passes with zero findings and risk score 0."""
    client, _ = client_and_db
    payload = {
        "content": 'def hello():\n    return "Safe application code"\n',
        "filename": "app.py",
    }
    resp = client.post("/api/scans/snippet", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "passed"
    assert data["risk_score"] == 0
    assert data["risk_level"] == "low"
    assert data["findings"] == []
    assert data["blocked_reason"] is None


def test_snippet_oversized_content_rejected(client_and_db):
    """Verify snippets exceeding 100 KB limit return 413 or 422."""
    client, _ = client_and_db
    large_content = "X" * (101 * 1024)
    payload = {
        "content": large_content,
        "filename": "large.py",
    }
    resp = client.post("/api/scans/snippet", json=payload)
    assert resp.status_code in (413, 422)


def test_snippet_filename_with_path_traversal_sanitized(client_and_db):
    """Verify filename with ../ is sanitized to plain basename."""
    client, _ = client_and_db
    payload = {
        "content": 'KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        "filename": "../../../etc/passwd/test.py",
    }
    resp = client.post("/api/scans/snippet", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["findings"]) >= 1
    assert data["findings"][0]["file"] == "test.py"

    # Also check traversal with only slashes/dots falls back to snippet.txt
    payload_fallback = {
        "content": 'print("clean")',
        "filename": "../../../",
    }
    resp_fallback = client.post("/api/scans/snippet", json=payload_fallback)
    assert resp_fallback.status_code == 200
    data_fallback = resp_fallback.json()
    assert data_fallback["status"] == "passed"


def test_snippet_does_not_persist_to_database(client_and_db):
    """Verify snippet scanner never saves records to the scans or findings tables."""
    client, db = client_and_db
    initial_count = db.query(ScanRecord).count()

    payload = {
        "content": 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n',
        "filename": "temp_snippet.py",
    }
    resp = client.post("/api/scans/snippet", json=payload)
    assert resp.status_code == 200

    after_count = db.query(ScanRecord).count()
    assert after_count == initial_count, "Snippet scan should never persist to ScanRecord table"
