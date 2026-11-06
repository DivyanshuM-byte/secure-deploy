from __future__ import annotations

import subprocess
import urllib.error
import urllib.request

from .base import Deployer
from .docker_build import run_docker_build, sanitize_identifier


class LocalDockerDeployer(Deployer):
    """Deployer using local Docker CLI with security hardening flags."""

    def build(self, project_path: str, tag: str) -> str:
        return run_docker_build(project_path, tag)

    def run(self, tag: str, name: str, port: int, env_file_path: str | None = None) -> str:
        safe_name = sanitize_identifier(name)
        # Ensure custom network exists
        subprocess.run(
            ["docker", "network", "create", "secure-deploy-net"],
            capture_output=True,
            text=True,
        )

        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            safe_name,
            "--network",
            "secure-deploy-net",
            "-p",
            f"127.0.0.1:{port}:80",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "100",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--restart",
            "unless-stopped",
        ]
        if env_file_path:
            cmd.extend(["--env-file", env_file_path])
        cmd.append(tag)

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(f"Local container run failed: {output}")
        return output

    def stop(self, name: str) -> None:
        safe_name = sanitize_identifier(name)
        subprocess.run(["docker", "stop", safe_name], capture_output=True, timeout=30)
        subprocess.run(["docker", "rm", "-f", safe_name], capture_output=True, timeout=30)

    def logs(self, name: str) -> str:
        safe_name = sanitize_identifier(name)
        proc = subprocess.run(
            ["docker", "logs", "--tail", "200", safe_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")

    def healthcheck(self, url: str) -> bool:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "secure-deploy-healthcheck"})
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 204, 301, 302, 404)
        except Exception:
            return False
