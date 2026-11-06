from collections import Counter
from datetime import datetime
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch
import zipfile

try:
    import pytest
except ImportError:
    class _PytestStub:
        @staticmethod
        def raises(expected_exception):
            class _Context:
                def __init__(self):
                    self.value = None

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_val, exc_tb):
                    if exc_type and issubclass(exc_type, expected_exception):
                        self.value = exc_val
                        return True
                    raise AssertionError(f"Expected {expected_exception} was not raised")

            return _Context()

    pytest = _PytestStub()  # type: ignore

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Regex for github verification
GITHUB_URL_REGEX = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$"
)


def create_in_memory_zip(file_dict: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in file_dict.items():
            zf.writestr(filename, content)
    buf.seek(0)
    return buf


def check_zip_security_inline(zf: zipfile.ZipFile, extract_dir: Path):
    infolist = zf.infolist()
    if len(infolist) > 5000:
        raise ValueError(f"ZIP contains {len(infolist)} files, exceeding limit of 5000")
    total_uncompressed = sum(info.file_size for info in infolist)
    if total_uncompressed > 100 * 1024 * 1024:
        raise ValueError(f"Uncompressed size exceeds 100 MB limit ({total_uncompressed})")
    for info in infolist:
        is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
        if is_symlink:
            raise ValueError(f"Prohibited symlink entry detected in ZIP: {info.filename}")
        dest = (extract_dir / info.filename).resolve()
        if not dest.is_relative_to(extract_dir.resolve()):
            raise ValueError(f"Zip-slip path traversal rejected: {info.filename}")


def test_zip_slip_rejected():
    """Verify zip archive with path traversal (zip-slip) entry is rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.py", "malicious_content = True\n")
        zf.writestr("app.py", "print('hello')\n")
    buf.seek(0)

    zf = zipfile.ZipFile(buf)
    with tempfile.TemporaryDirectory() as tmp_dir:
        extract_dir = Path(tmp_dir)
        try:
            check_zip_security_inline(zf, extract_dir)
            assert False, "Should have raised ValueError on zip slip"
        except ValueError as exc:
            assert "Zip-slip" in str(exc) or "traversal" in str(exc).lower()


def test_zip_bomb_rejected():
    """Verify zip archive exceeding uncompressed size or file count is rejected."""
    # Case 1: Exceeds 5000 files limit
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(5005):
            zf.writestr(f"file_{i}.txt", "")
    buf.seek(0)

    zf = zipfile.ZipFile(buf)
    with tempfile.TemporaryDirectory() as tmp_dir:
        extract_dir = Path(tmp_dir)
        try:
            check_zip_security_inline(zf, extract_dir)
            assert False, "Should have raised ValueError on file count limit"
        except ValueError as exc:
            assert "5000" in str(exc)

    # Case 2: Exceeds 100 MB uncompressed limit
    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w") as zf2:
        zf2.writestr("test.txt", "small")
    buf2.seek(0)
    zf2 = zipfile.ZipFile(buf2)
    zf2.infolist()[0].file_size = 150 * 1024 * 1024  # Manipulate parsed uncompressed header
    with tempfile.TemporaryDirectory() as tmp_dir:
        extract_dir = Path(tmp_dir)
        try:
            check_zip_security_inline(zf2, extract_dir)
            assert False, "Should have raised ValueError on 100MB limit"
        except ValueError as exc:
            assert "100 MB" in str(exc)


def test_valid_zip_scanned_and_temp_cleaned_up():
    """Verify a valid zip is accepted, scanned, and temporary directory is cleaned up."""
    from scanner.engine import run_all_scans

    zip_buf = create_in_memory_zip({
        "service.js": 'const awsKey = "AKIAIOSFODNN7EXAMPLE";\n',
        "clean.py": "def add(a, b): return a + b\n",
    })

    zf = zipfile.ZipFile(zip_buf)
    with tempfile.TemporaryDirectory() as tmp_dir:
        extract_dir = Path(tmp_dir) / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        check_zip_security_inline(zf, extract_dir)
        zf.extractall(extract_dir)

        scan_result = run_all_scans(str(extract_dir))
        assert scan_result.status == "blocked"
        assert any(f.type == "aws_access_key" for f in scan_result.findings)

        # Cleanup verification
        shutil.rmtree(extract_dir, ignore_errors=True)
        assert not extract_dir.exists(), "Extracted folder should be deleted"


def test_invalid_github_urls_rejected():
    """Verify dangerous, non-HTTPS, or invalid domain GitHub URLs are rejected."""
    invalid_urls = [
        "file:///etc/passwd",
        "ssh://git@github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "https://github.com/owner/repo; rm -rf /",
        "https://github.com/owner/repo && echo pwned",
        "https://github.com/owner/$(whoami)",
        "http://github.com/owner/repo",
    ]

    for url in invalid_urls:
        assert not GITHUB_URL_REGEX.match(url), f"URL should be rejected: {url}"

    valid_urls = [
        "https://github.com/torvalds/linux",
        "https://github.com/fastapi/fastapi.git",
        "https://github.com/psf/requests/",
    ]
    for url in valid_urls:
        assert GITHUB_URL_REGEX.match(url) is not None, f"URL should be accepted: {url}"


def test_github_clone_mocked_subprocess():
    """Verify GitHub clone logic using mocked subprocess (no real network connection)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        clone_dir = Path(tmp_dir) / "cloned_repo"

        def mock_clone_success(cmd, capture_output, text, timeout, env):
            target_dir = Path(cmd[-1])
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "index.js").write_text('const k = "AKIAIOSFODNN7EXAMPLE";\n', encoding="utf-8")
            res = MagicMock()
            res.returncode = 0
            res.stdout = "Cloned successfully"
            res.stderr = ""
            return res

        repo_url = "https://github.com/test/repo"
        branch = "main"
        cmd = ["git", "clone", "--depth", "1", "--single-branch", "-b", branch, repo_url, str(clone_dir)]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}

        with patch("subprocess.run", side_effect=mock_clone_success) as mock_run:
            proc = mock_run(cmd, capture_output=True, text=True, timeout=60, env=env)
            assert proc.returncode == 0

            args, kwargs = mock_run.call_args
            assert args[0][0] == "git"
            assert "clone" in args[0]
            assert kwargs.get("shell") is not True
            assert kwargs.get("timeout") == 60
            assert kwargs.get("env", {}).get("GIT_TERMINAL_PROMPT") == "0"

        from scanner.engine import run_all_scans
        scan_result = run_all_scans(str(clone_dir))
        assert scan_result.status == "blocked"
        assert len(scan_result.findings) >= 1

        shutil.rmtree(clone_dir, ignore_errors=True)
        assert not clone_dir.exists(), "Clone directory should be deleted"

        # Failure case
        def mock_clone_fail(cmd, capture_output, text, timeout, env):
            res = MagicMock()
            res.returncode = 128
            res.stderr = "fatal: repository 'https://github.com/private/repo' not found"
            return res

        with patch("subprocess.run", side_effect=mock_clone_fail) as mock_fail_run:
            proc_fail = mock_fail_run(["git", "clone", "https://github.com/private/repo", str(clone_dir)], capture_output=True, text=True, timeout=60, env=env)
            assert proc_fail.returncode == 128
            assert "not found" in proc_fail.stderr


def test_stats_endpoint():
    """Verify statistics calculation aggregates totals, severities, and averages."""
    findings = [
        {"severity": "critical", "type": "aws_key"},
        {"severity": "critical", "type": "stripe_key"},
        {"severity": "high", "type": "pan"},
        {"severity": "medium", "type": "email"},
    ]
    scans = [
        {"id": 1, "status": "blocked", "risk_score": 85},
        {"id": 2, "status": "passed", "risk_score": 15},
    ]

    total_scans = len(scans)
    blocked_count = sum(1 for s in scans if s["status"] == "blocked")
    passed_count = sum(1 for s in scans if s["status"] == "passed")
    total_findings = len(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_counts[f["severity"]] += 1

    avg_risk_score = round(sum(s["risk_score"] for s in scans) / len(scans), 1)

    assert total_scans == 2
    assert blocked_count == 1
    assert passed_count == 1
    assert total_findings == 4
    assert severity_counts["critical"] == 2
    assert severity_counts["high"] == 1
    assert avg_risk_score == 50.0


def test_status_transitions():
    """Verify status transitions: queued -> running -> passed/blocked."""
    from scanner.engine import run_all_scans

    _sample_repos = Path(__file__).resolve().parent / "sample-repos"

    status = "queued"
    assert status == "queued"

    status = "running"
    assert status == "running"

    result = run_all_scans(str(_sample_repos / "clean-app"))
    status = result.status
    assert status == "passed"
    assert result.risk_score == 0

    blocked_result = run_all_scans(str(_sample_repos / "leaky-app"))
    status = blocked_result.status
    assert status == "blocked"
    assert blocked_result.risk_score >= 40


def test_github_clone_timeout_expired_fails_and_blocks_deploy():
    """Prove a timed-out clone (mock subprocess.TimeoutExpired) gives status 'failed'
    with the new message and that /deploy returns 409 for it."""
    import subprocess
    from datetime import datetime, timezone
    from fastapi.testclient import TestClient
    from main import app
    from db import ScanRecord, SessionLocal, init_db
    from api.scans import clone_and_scan_github_task, get_git_clone_timeout

    init_db()
    db = SessionLocal()
    try:
        # 1. Verify default timeout (120) and range boundaries
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GIT_CLONE_TIMEOUT_SECONDS", None)
            assert get_git_clone_timeout() == 120

        with patch.dict(os.environ, {"GIT_CLONE_TIMEOUT_SECONDS": "25"}):
            # 25 is out of allowed range 30-600 -> fallback to default 120
            assert get_git_clone_timeout() == 120

        with patch.dict(os.environ, {"GIT_CLONE_TIMEOUT_SECONDS": "1000"}):
            # 1000 is out of allowed range 30-600 -> fallback to default 120
            assert get_git_clone_timeout() == 120

        # 2. Test configured timeout in range (e.g., 180 seconds)
        with patch.dict(os.environ, {"GIT_CLONE_TIMEOUT_SECONDS": "180"}):
            assert get_git_clone_timeout() == 180

            scan = ScanRecord(
                source="https://github.com/large-org/huge-repo",
                status="queued",
                risk_score=0,
                risk_level="low",
                created_at=datetime.now(timezone.utc),
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            scan_id = scan.id

            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["git", "clone"], timeout=180)):
                clone_and_scan_github_task(scan_id, "https://github.com/large-org/huge-repo", None)

            db.refresh(scan)
            assert scan.status == "failed"
            expected_msg = (
                "Git clone timed out after 180 seconds. "
                "The repository may be too large; try a smaller repo or increase GIT_CLONE_TIMEOUT_SECONDS."
            )
            assert scan.blocked_reason == expected_msg

            # 3. Test that /deploy returns 409 Conflict
            client = TestClient(app)
            deploy_resp = client.post(f"/api/scans/{scan_id}/deploy")
            assert deploy_resp.status_code == 409
            assert "Only scans with status 'passed' can be deployed" in deploy_resp.json()["detail"]
    finally:
        db.close()


if __name__ == "__main__":
    test_zip_slip_rejected()
    test_zip_bomb_rejected()
    test_valid_zip_scanned_and_temp_cleaned_up()
    test_invalid_github_urls_rejected()
    test_github_clone_mocked_subprocess()
    test_stats_endpoint()
    test_status_transitions()
    test_github_clone_timeout_expired_fails_and_blocks_deploy()
    print("ALL 8 test_day3.py checks PASSED successfully!")
