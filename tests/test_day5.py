from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
from unittest.mock import MagicMock, patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.deployments import DeploymentOut, execute_deployment_task, sanitize_logs
from db import Base, DeploymentRecord, ProbeResultRecord, ScanRecord, SessionLocal, engine, init_db
from deployer.docker_build import DOCKERIGNORE_CONTENT
from deployer.local import LocalDockerDeployer
from deployer.probe import ProbeResult, looks_like_real_file, probe_deployment
from fastapi.testclient import TestClient
from main import app
from secrets_store import (
    LocalEncryptedStore,
    SSMStore,
    SecretValidationError,
    get_secrets_store,
)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()


# =====================================================================
# PART A: SECRETS MANAGEMENT TESTS
# =====================================================================

def test_local_encrypted_store_crud_roundtrip(tmp_path):
    """LocalEncryptedStore put, get_all, list_names, and delete work correctly."""
    key_file = tmp_path / ".secrets_master.key"
    store_file = tmp_path / ".secrets_store.json"

    store = LocalEncryptedStore(key_file_path=key_file, store_file_path=store_file)
    project = "my-test-app"

    # Put secrets
    store.put(project, "API_KEY", "super-secret-token-123")
    store.put(project, "DB_PASS", "database-password-456")

    # List names (values not returned)
    names = store.list_names(project)
    assert names == ["API_KEY", "DB_PASS"]

    # Decrypt all
    decrypted = store.get_all(project)
    assert decrypted["API_KEY"] == "super-secret-token-123"
    assert decrypted["DB_PASS"] == "database-password-456"

    # Verify plaintext is NOT stored in the file on disk
    raw_content = store_file.read_text(encoding="utf-8")
    assert "super-secret-token-123" not in raw_content
    assert "database-password-456" not in raw_content
    assert "gAAAAA" in raw_content  # Fernet token prefix

    # Delete secret
    deleted = store.delete(project, "API_KEY")
    assert deleted is True
    assert store.list_names(project) == ["DB_PASS"]
    assert "API_KEY" not in store.get_all(project)

    # Delete non-existent
    assert store.delete(project, "NON_EXISTENT") is False


def test_secrets_store_validation_rules(tmp_path):
    """Validates slugs, uppercase names, reserved names, newlines, and length limit."""
    store = LocalEncryptedStore(
        key_file_path=tmp_path / "key", store_file_path=tmp_path / "store.json"
    )

    # 1. Invalid project slug
    with pytest.raises(SecretValidationError, match="Invalid project slug"):
        store.put("Invalid_Slug!", "API_KEY", "valid-value")

    # 2. Invalid secret name (must be uppercase start)
    with pytest.raises(SecretValidationError, match="Invalid secret name"):
        store.put("valid-slug", "api_key", "valid-value")

    # 3. Reserved environment variable names
    for reserved in ["PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "HOME", "SHELL"]:
        with pytest.raises(SecretValidationError, match="reserved"):
            store.put("valid-slug", reserved, "valid-value")

    # 4. Newline in value prohibited
    with pytest.raises(SecretValidationError, match="newline"):
        store.put("valid-slug", "SECRET_KEY", "line1\nline2")

    with pytest.raises(SecretValidationError, match="newline"):
        store.put("valid-slug", "SECRET_KEY", "line1\rline2")

    # 5. Oversized secret value (>4096 chars)
    oversized = "A" * 4097
    with pytest.raises(SecretValidationError, match="maximum allowed length"):
        store.put("valid-slug", "LONG_KEY", oversized)


def test_secrets_api_write_only_and_no_value_leakage(tmp_path):
    """PUT /api/projects/{slug}/secrets/{name} is write-only; GET returns fixed constant masked bullets."""
    client = TestClient(app)
    project = "api-test-proj"
    secret_name = "STRIPE_SECRET"
    secret_val = "sk_live_verysecretstripekey999"

    # PUT secret
    put_resp = client.put(
        f"/api/projects/{project}/secrets/{secret_name}",
        json={"value": secret_val},
    )
    assert put_resp.status_code == 200
    # Crucial: The submitted secret value must NEVER be echoed in response
    assert secret_val not in put_resp.text
    assert put_resp.json()["status"] == "stored"

    # GET secrets list
    get_resp = client.get(f"/api/projects/{project}/secrets")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert len(data) >= 1
    found = next((item for item in data if item["name"] == secret_name), None)
    assert found is not None
    # Crucial: Value is never returned, and masked is a fixed constant
    assert found["masked"] == "••••••••"
    assert "value" not in found
    assert secret_val not in get_resp.text

    # Validation failure does NOT echo the invalid submitted value back
    bad_val = "my_leaked_secret_token_12345\nwith_newline"
    err_resp = client.put(
        f"/api/projects/{project}/secrets/BAD_SECRET",
        json={"value": bad_val},
    )
    assert err_resp.status_code in (400, 422)
    assert "my_leaked_secret_token_12345" not in err_resp.text


def test_ssm_store_calls_parameter_store_with_secure_string():
    """SSMStore uses AWS Parameter Store with Type=SecureString and default credential chain."""
    mock_ssm = MagicMock()
    mock_ssm.get_parameters_by_path.return_value = {"Parameters": [], "NextToken": None}
    store = SSMStore(region_name="ap-south-1", client=mock_ssm)

    # Test put
    store.put("cloud-app", "DB_PASSWORD", "dbpass-cloud-secret")
    mock_ssm.put_parameter.assert_called_once_with(
        Name="/secure-deploy/cloud-app/DB_PASSWORD",
        Value="dbpass-cloud-secret",
        Type="SecureString",
        Overwrite=True,
    )

    # Test get_all
    mock_ssm.get_parameters_by_path.return_value = {
        "Parameters": [
            {"Name": "/secure-deploy/cloud-app/DB_PASSWORD", "Value": "dbpass-cloud-secret"}
        ]
    }
    secrets = store.get_all("cloud-app")
    assert secrets == {"DB_PASSWORD": "dbpass-cloud-secret"}
    mock_ssm.get_parameters_by_path.assert_called_with(
        Path="/secure-deploy/cloud-app/",
        WithDecryption=True,
        Recursive=True,
    )

    # Test delete
    store.delete("cloud-app", "DB_PASSWORD")
    mock_ssm.delete_parameter.assert_called_once_with(
        Name="/secure-deploy/cloud-app/DB_PASSWORD"
    )


# =====================================================================
# RUNTIME INJECTION & LOG REDACTION TESTS
# =====================================================================

def test_runtime_env_file_created_with_0600_and_deleted_on_failure():
    """Secrets env-file is created with 0600 mode and deleted in finally block even when docker run fails."""
    # Create clean mock deployment in DB
    db = SessionLocal()
    scan = ScanRecord(source="clean-test", status="passed", risk_score=0, risk_level="low")
    db.add(scan)
    db.commit()

    dep = DeploymentRecord(
        scan_id=scan.id,
        project="inject-test-proj",
        status="pending",
        image_tag="test/image:v1",
        container_name="test-c-fail",
        port=9010,
        url="http://127.0.0.1:9010",
        host_type="local",
        logs="",
    )
    db.add(dep)
    db.commit()
    dep_id = dep.id
    db.close()

    # Pre-populate secrets for this project
    store = get_secrets_store()
    store.put("inject-test-proj", "API_TOKEN", "supersecret123")

    captured_env_file: list[str] = []

    def mock_run_with_inspection(*args, **kwargs):
        env_file = kwargs.get("env_file_path")
        if env_file:
            captured_env_file.append(env_file)
            # Verify permissions are strictly 0600
            file_mode = os.stat(env_file).st_mode & 0o777
            assert file_mode == 0o600, f"Expected 0600 permissions, got {oct(file_mode)}"
            # Verify plaintext secret is in env file
            assert "API_TOKEN=supersecret123" in Path(env_file).read_text(encoding="utf-8")
        # Intentionally raise an error to ensure finally cleanup runs
        raise RuntimeError("Simulated docker engine failure")

    with patch("api.deployments.run_all_scans") as mock_scan, \
         patch("api.deployments.get_deployer") as mock_deployer_fac:
        mock_scan_res = MagicMock()
        mock_scan_res.status = "passed"
        mock_scan.return_value = mock_scan_res

        deployer_instance = MagicMock()
        deployer_instance.build.return_value = "Build successful"
        deployer_instance.run.side_effect = mock_run_with_inspection
        mock_deployer_fac.return_value = deployer_instance

        # Execute deployment task
        with tempfile.TemporaryDirectory() as tmp_proj:
            execute_deployment_task(dep_id, tmp_proj, project_slug="inject-test-proj")

    assert len(captured_env_file) == 1
    # Verify the env-file was deleted immediately in the finally block
    assert not os.path.exists(captured_env_file[0]), "Temporary env file was not deleted after execution"


def test_docker_run_command_never_contains_minus_e_and_redacts_logs():
    """LocalDockerDeployer uses --env-file rather than -e NAME=value, and sanitize_logs redacts values and base64 forms."""
    deployer = LocalDockerDeployer()
    with patch("subprocess.run") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "container-id-ok"
        mock_proc.stderr = ""
        mock_sub.return_value = mock_proc

        deployer.run("my-tag", "my-container", 9022, env_file_path="/tmp/test.env")

        cmd = mock_sub.call_args[0][0]
        assert "--env-file" in cmd
        assert "/tmp/test.env" in cmd
        assert "-e" not in cmd

    # Test log redactor
    raw_secret = "ConfidentialPassword99!"
    b64_secret = base64.b64encode(raw_secret.encode("utf-8")).decode("utf-8")

    sample_logs = (
        f"Server starting with secret: {raw_secret}\n"
        f"Base64 encoded auth header: Authorization: Basic {b64_secret}\n"
        "Normal operation completed."
    )
    cleaned = sanitize_logs(sample_logs, secret_values=[raw_secret])
    assert raw_secret not in cleaned
    assert b64_secret not in cleaned
    assert "****" in cleaned


def test_dockerignore_excludes_all_secret_env_patterns():
    """.dockerignore content extends rules to exclude .env*, *.secrets, and .secrets_*."""
    assert ".env*" in DOCKERIGNORE_CONTENT
    assert "*.secrets" in DOCKERIGNORE_CONTENT
    assert ".secrets_*" in DOCKERIGNORE_CONTENT


# =====================================================================
# PART B: POST-DEPLOY PROBE TESTS
# =====================================================================

class MockServerHandler(BaseHTTPRequestHandler):
    mode = "clean"  # "leaky", "clean", "spa", "homepage_secret"
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes, content_type: str = "text/plain", extra_headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Baseline checks
        if "__sd_probe_baseline_" in self.path:
            if self.mode == "spa":
                self._send(200, b"<!DOCTYPE html><html><body>Single Page App Fallback</body></html>", "text/html")
            else:
                self._send(404, b"Not Found")
            return

        if self.mode == "spa":
            self._send(200, b"<!DOCTYPE html><html><body>Single Page App Fallback</body></html>", "text/html")
            return

        if self.mode == "leaky":
            if self.path == "/.env":
                self._send(200, b"DATABASE_PASSWORD=leaked_password_123\nSECRET_KEY=leaked_key_456\n")
                return
            if self.path == "/.git/config":
                self._send(200, b"[core]\nrepositoryformatversion = 0\nfilemode = true\n")
                return

        if self.mode == "homepage_secret" and self.path == "/":
            self._send(
                200,
                b"<html><body><h1>Welcome</h1><script>const key = 'AKIAIOSFODNN7EXAMPLE';</script></body></html>",
                "text/html",
                {"Server": "nginx/1.24.0"},
            )
            return

        # Default clean 404
        self._send(404, b"404 Not Found")

    def log_message(self, format, *args):
        # Suppress server access logs during tests
        pass


@pytest.fixture
def mock_server():
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockServerHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def set_mode(mode: str):
        MockServerHandler.mode = mode

    yield f"http://127.0.0.1:{port}", set_mode
    server.shutdown()
    server.server_close()


def test_probe_detects_leaky_sensitive_files(mock_server):
    """Probe marks /.env and /.git/config as EXPOSED when real sensitive content signatures are served."""
    base_url, set_mode = mock_server
    set_mode("leaky")

    result = probe_deployment(base_url, verify_tls=False)
    assert result.overall_verdict == "exposed"
    assert result.exposed_count >= 2

    env_item = next((i for i in result.items if i.path == "/.env"), None)
    assert env_item is not None
    assert env_item.verdict == "exposed"
    assert env_item.status == 200

    git_item = next((i for i in result.items if i.path == "/.git/config"), None)
    assert git_item is not None
    assert git_item.verdict == "exposed"


def test_probe_clean_server_returns_safe_or_warning_only(mock_server):
    """Clean server returning 404 for sensitive files has 0 exposed items."""
    base_url, set_mode = mock_server
    set_mode("clean")

    result = probe_deployment(base_url, verify_tls=False)
    assert result.exposed_count == 0
    # Any warnings are only for missing security headers on 404
    for item in result.items:
        if item.path in ("/.env", "/.git/config", "/.git/HEAD", "/id_rsa"):
            assert item.verdict == "safe"


def test_probe_spa_fallback_is_not_mistaken_for_exposure(mock_server):
    """SPA catch-all 200 server returning the same HTML for all routes is recognized as baseline and NOT marked exposed."""
    base_url, set_mode = mock_server
    set_mode("spa")

    result = probe_deployment(base_url, verify_tls=False)
    # None of the sensitive paths should be flagged as exposed
    for item in result.items:
        if item.path.startswith("/."):
            assert item.verdict != "exposed", f"Path {item.path} falsely flagged as exposed on SPA server"


def test_probe_homepage_detects_bundled_secrets_with_masked_preview(mock_server):
    """Detects AWS access key bundled into served homepage and masks preview in probe findings."""
    base_url, set_mode = mock_server
    set_mode("homepage_secret")

    result = probe_deployment(base_url, verify_tls=False)
    assert result.overall_verdict == "exposed"

    hp_item = next((i for i in result.items if i.path == "/" and i.verdict == "exposed"), None)
    assert hp_item is not None
    assert "AKIA****" in hp_item.note
    assert "AKIAIOSFODNN7EXAMPLE" not in hp_item.note

    # Server header revealing version is flagged as warning
    server_hdr = next((i for i in result.items if i.path == "headers/Server"), None)
    assert server_hdr is not None
    assert server_hdr.verdict == "warning"


def test_probe_ssrf_safety_refuses_unauthorized_hosts():
    """Probe strictly refuses non-loopback or unauthorized hosts."""
    with pytest.raises(ValueError, match="SSRF safety violation"):
        probe_deployment("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(ValueError, match="SSRF safety violation"):
        probe_deployment("http://malicious-external-server.com/evil")


def test_exposed_probe_triggers_auto_stop():
    """When AUTO_STOP_ON_EXPOSURE=true, an exposed probe finding triggers deployer.stop and marks status 'exposed'."""
    db = SessionLocal()
    scan = ScanRecord(source="clean-test", status="passed", risk_score=0, risk_level="low")
    db.add(scan)
    db.commit()

    dep = DeploymentRecord(
        scan_id=scan.id,
        project="probe-stop-test",
        status="pending",
        image_tag="test/image:v1",
        container_name="test-c-exposed",
        port=9030,
        url="http://127.0.0.1:9030",
        host_type="local",
        logs="",
    )
    db.add(dep)
    db.commit()
    dep_id = dep.id
    db.close()

    mock_exposed_res = ProbeResult(
        items=[],
        overall_verdict="exposed",
        exposed_count=1,
        warning_count=0,
    )

    with patch("api.deployments.run_all_scans") as mock_scan, \
         patch("api.deployments.get_deployer") as mock_deployer_fac, \
         patch("api.deployments.probe_deployment", return_value=mock_exposed_res), \
         patch.dict(os.environ, {"AUTO_STOP_ON_EXPOSURE": "true"}):

        mock_scan_res = MagicMock()
        mock_scan_res.status = "passed"
        mock_scan.return_value = mock_scan_res

        deployer_instance = MagicMock()
        deployer_instance.build.return_value = "Build OK"
        deployer_instance.run.return_value = "Container started"
        mock_deployer_fac.return_value = deployer_instance

        with tempfile.TemporaryDirectory() as tmp_proj:
            execute_deployment_task(dep_id, tmp_proj)

        # Verify deployer.stop was invoked
        deployer_instance.stop.assert_called_once_with("test-c-exposed")

    # Check database status
    db = SessionLocal()
    updated_dep = db.query(DeploymentRecord).filter(DeploymentRecord.id == dep_id).first()
    assert updated_dep.status == "exposed"
    assert "AUTO_STOP_ON_EXPOSURE=true" in updated_dep.logs
    db.close()
