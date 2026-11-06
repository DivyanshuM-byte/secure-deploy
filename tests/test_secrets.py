from pathlib import Path
import sys

# Ensure backend package is importable when running pytest from repo root
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

try:
    import pytest
except ImportError:
    pytest = None  # type: ignore

try:
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from db import Base, get_db  # noqa: E402
    from main import app  # noqa: E402
except ImportError:
    TestClient = None  # type: ignore
from scanner.secrets import scan_directory, scan_file  # noqa: E402

SAMPLE_REPO = Path(__file__).resolve().parent / "sample-repos" / "leaky-app"

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_STRIPE_KEY = "sk_local_testdummyfakeforsecure56"
FAKE_GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"


def test_each_fake_secret_is_detected() -> None:
    """Verify .env, fake AWS key, and fake Stripe key are all detected in leaky-app."""
    findings = scan_directory(str(SAMPLE_REPO))
    finding_types = {f.type for f in findings}
    finding_files = {f.file for f in findings}

    assert "committed_env_file" in finding_types
    assert "aws_access_key" in finding_types
    assert "stripe_live_key" in finding_types
    assert ".env" in finding_files
    assert "config.js" in finding_files

    # Ensure critical severity on .env, AWS key, and Stripe live key
    critical_types = {f.type for f in findings if f.severity == "critical"}
    assert {"committed_env_file", "aws_access_key", "stripe_live_key"}.issubset(critical_types)


def test_clean_file_gives_zero_findings() -> None:
    """Verify scanning clean.py produces zero findings."""
    clean_file = SAMPLE_REPO / "clean.py"
    findings = scan_file(clean_file, "clean.py")
    assert findings == []

    # Also ensure clean.py never appears in the full directory scan
    dir_findings = scan_directory(str(SAMPLE_REPO))
    assert all(f.file != "clean.py" for f in dir_findings)


def test_masked_preview_never_contains_full_secret() -> None:
    """Ensure masked_preview only exposes first 4 and last 2 characters."""
    findings = scan_directory(str(SAMPLE_REPO))
    assert len(findings) > 0

    raw_secrets = [
        FAKE_AWS_KEY,
        FAKE_STRIPE_KEY,
        FAKE_GITHUB_TOKEN,
        "super_secret_db_password_for_testing_99",
        "x9K2mP8qL4vR7wY1zB5nC3jF6hG0dS8aQ2wE",
    ]

    for finding in findings:
        assert "****" in finding.masked_preview
        for secret in raw_secrets:
            assert secret not in finding.masked_preview

    aws_finding = next(f for f in findings if f.type == "aws_access_key")
    assert aws_finding.masked_preview == "AKIA****LE"

    stripe_finding = next(f for f in findings if f.type == "stripe_live_key")
    assert stripe_finding.masked_preview == "sk_l****56"


def test_node_modules_is_skipped(tmp_path: Path) -> None:
    """Ensure files inside node_modules (and other ignored dirs) are never scanned."""
    nm_dir = tmp_path / "node_modules" / "some-pkg"
    nm_dir.mkdir(parents=True)
    (nm_dir / "index.js").write_text(
        f'const leaked = "{FAKE_AWS_KEY}";\n',
        encoding="utf-8",
    )

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("print('clean app')\n", encoding="utf-8")

    findings = scan_directory(str(tmp_path))
    assert findings == []


def test_api_scan_endpoints() -> None:
    """Verify POST /api/scans, GET /api/scans, and GET /api/scans/{id}."""
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

    try:
        post_resp = client.post("/api/scans", json={"path": str(SAMPLE_REPO)})
        assert post_resp.status_code == 201
        created = post_resp.json()
        assert created["status"] == "blocked"
        assert len(created["findings"]) >= 3

        list_resp = client.get("/api/scans")
        assert list_resp.status_code == 200
        scans_list = list_resp.json()
        assert len(scans_list) == 1
        assert scans_list[0]["id"] == created["id"]

        detail_resp = client.get(f"/api/scans/{created['id']}")
        assert detail_resp.status_code == 200
        assert detail_resp.json()["id"] == created["id"]
    finally:
        app.dependency_overrides.clear()


if __name__ == "__main__":
    test_each_fake_secret_is_detected()
    test_clean_file_gives_zero_findings()
    test_masked_preview_never_contains_full_secret()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        test_node_modules_is_skipped(Path(tmp))
    print("ALL test_secrets.py core checks PASSED successfully!")
