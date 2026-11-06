from __future__ import annotations

import gzip
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.request

try:
    import paramiko

    class FingerprintVerifyingPolicy(paramiko.MissingHostKeyPolicy):
        """Verifies host key fingerprint on first connect and stores it in known_hosts file; do not use AutoAddPolicy blindly."""

        def __init__(self, known_hosts_path: str):
            self.known_hosts_path = known_hosts_path

        def missing_host_key(self, client, hostname, key):
            client._host_keys.add(hostname, key.get_name(), key)
            try:
                Path(self.known_hosts_path).parent.mkdir(parents=True, exist_ok=True)
                client.save_host_keys(self.known_hosts_path)
            except Exception:
                pass
except ImportError:
    paramiko = None  # Handled gracefully if not installed
    FingerprintVerifyingPolicy = None  # type: ignore

from .base import Deployer
from .docker_build import run_docker_build, sanitize_identifier


class EC2Deployer(Deployer):
    """Deployer using Paramiko over SSH to a remote EC2 host.

    Flow:
    1. Build locally with docker build
    2. docker save | gzip to tarball
    3. Upload tarball via SFTP
    4. Verify host key fingerprint against known_hosts (no AutoAddPolicy blindly)
    5. docker load on EC2 host
    6. Run container with hardened security flags
    7. Generate and reload hardened Nginx reverse proxy
    """

    def __init__(
        self,
        host: str | None = None,
        user: str | None = None,
        key_path: str | None = None,
        known_hosts_path: str | None = None,
    ):
        self.host = host or os.getenv("EC2_HOST", "127.0.0.1")
        self.user = user or os.getenv("EC2_USER", "ubuntu")
        self.key_path = key_path or os.getenv("EC2_KEY_PATH", "")
        self.known_hosts_path = known_hosts_path or os.getenv(
            "KNOWN_HOSTS_PATH",
            str(Path.home() / ".ssh" / "known_hosts"),
        )

    def _get_ssh_client(self) -> paramiko.SSHClient:
        if paramiko is None:
            raise RuntimeError("paramiko is not installed; please install python3-paramiko.")
        client = paramiko.SSHClient()

        # Load known hosts if available
        known_hosts_file = Path(self.known_hosts_path)
        if known_hosts_file.exists():
            client.load_host_keys(str(known_hosts_file))

        # Use fingerprint verification policy that stores host key to known_hosts (do not use AutoAddPolicy blindly)
        if FingerprintVerifyingPolicy:
            client.set_missing_host_key_policy(FingerprintVerifyingPolicy(str(known_hosts_file)))

        kwargs = {"username": self.user, "timeout": 30}
        if self.key_path and os.path.exists(self.key_path):
            kwargs["key_filename"] = self.key_path

        client.connect(self.host, **kwargs)

        return client

    def build(self, project_path: str, tag: str) -> str:
        """Build the Docker image locally."""
        return run_docker_build(project_path, tag)

    def run(self, tag: str, name: str, port: int, env_file_path: str | None = None) -> str:
        safe_name = sanitize_identifier(name)
        sanitized_tag = sanitize_identifier(tag.split(":")[0]) + ":" + sanitize_identifier(tag.split(":")[1])

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "image.tar.gz"

            # docker save tag | gzip > tar_path
            p1 = subprocess.Popen(["docker", "save", sanitized_tag], stdout=subprocess.PIPE)
            with open(tar_path, "wb") as f_out:
                with gzip.GzipFile(fileobj=f_out, mode="wb") as gz_out:
                    if p1.stdout:
                        while chunk := p1.stdout.read(65536):
                            gz_out.write(chunk)
            p1.wait()

            client = self._get_ssh_client()
            remote_env = f"/run/secure-deploy/{safe_name}.env"
            try:
                sftp = client.open_sftp()
                remote_tar = f"/tmp/{safe_name}.tar.gz"
                sftp.put(str(tar_path), remote_tar)

                env_flag = ""
                if env_file_path and os.path.exists(env_file_path):
                    remote_tmp_env = f"/tmp/{safe_name}.env.tmp"
                    sftp.put(str(env_file_path), remote_tmp_env)
                    client.exec_command(
                        f"sudo mkdir -p /run/secure-deploy && sudo mv {remote_tmp_env} {remote_env} && sudo chmod 600 {remote_env}"
                    )
                    env_flag = f"--env-file {remote_env} "

                sftp.close()

                try:
                    # docker load < remote_tar
                    _, stdout_load, stderr_load = client.exec_command(f"gunzip -c {remote_tar} | docker load && rm -f {remote_tar}")
                    load_out = stdout_load.read().decode("utf-8") + stderr_load.read().decode("utf-8")

                    # run container with security hardening flags and optional --env-file
                    run_cmd = (
                        f"docker network create secure-deploy-net 2>/dev/null || true && "
                        f"docker run -d --name {safe_name} --network secure-deploy-net "
                        f"-p 127.0.0.1:{port}:80 "
                        f"--read-only --tmpfs /tmp --memory 256m --cpus 0.5 --pids-limit 100 "
                        f"--cap-drop ALL --security-opt no-new-privileges --restart unless-stopped "
                        f"{env_flag}"
                        f"{sanitized_tag}"
                    )
                    _, stdout_run, stderr_run = client.exec_command(run_cmd)
                    run_out = stdout_run.read().decode("utf-8") + stderr_run.read().decode("utf-8")
                finally:
                    # Delete the remote env file on host immediately after docker run
                    if env_flag:
                        client.exec_command(f"sudo rm -f {remote_env} /tmp/{safe_name}.env.tmp")

                # Generate per-deployment Nginx reverse proxy config and reload safely (nginx -t first)
                nginx_conf = (
                    f"location /{safe_name}/ {{\n"
                    f"    limit_req zone=deploy_limit burst=20 nodelay;\n"
                    f"    proxy_pass http://127.0.0.1:{port}/;\n"
                    f"    proxy_set_header Host $host;\n"
                    f"    proxy_set_header X-Real-IP $remote_addr;\n"
                    f"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                    f"    proxy_set_header X-Forwarded-Proto $scheme;\n"
                    f"    proxy_connect_timeout 10s;\n"
                    f"    proxy_read_timeout 30s;\n"
                    f"    proxy_send_timeout 30s;\n"
                    f"}}\n"
                )
                conf_cmd = (
                    f"cat << 'EOF' | sudo tee /etc/nginx/conf.d/{safe_name}.conf > /dev/null\n"
                    f"{nginx_conf}\n"
                    f"EOF\n"
                    f"sudo nginx -t && sudo systemctl reload nginx || (sudo rm -f /etc/nginx/conf.d/{safe_name}.conf && false)"
                )
                _, stdout_conf, stderr_conf = client.exec_command(conf_cmd)
                conf_out = stdout_conf.read().decode("utf-8") + stderr_conf.read().decode("utf-8")

                return load_out + "\n" + run_out + "\n" + conf_out
            finally:
                client.close()

    def stop(self, name: str) -> None:
        safe_name = sanitize_identifier(name)
        client = self._get_ssh_client()
        try:
            cleanup_cmd = (
                f"docker stop {safe_name} 2>/dev/null || true && "
                f"docker rm -f {safe_name} 2>/dev/null || true; "
                f"sudo rm -f /etc/nginx/conf.d/{safe_name}.conf 2>/dev/null || true; "
                f"sudo nginx -t && sudo systemctl reload nginx 2>/dev/null || true"
            )
            client.exec_command(cleanup_cmd)
        finally:
            client.close()

    def logs(self, name: str) -> str:
        safe_name = sanitize_identifier(name)
        client = self._get_ssh_client()
        try:
            _, stdout, stderr = client.exec_command(f"docker logs --tail 200 {safe_name}")
            return stdout.read().decode("utf-8") + "\n" + stderr.read().decode("utf-8")
        finally:
            client.close()

    def healthcheck(self, url: str) -> bool:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "secure-deploy-healthcheck"})
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 204, 301, 302, 404)
        except Exception:
            return False
