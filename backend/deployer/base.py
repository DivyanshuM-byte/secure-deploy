from __future__ import annotations

from abc import ABC, abstractmethod


class Deployer(ABC):
    """Abstract interface for multi-target container deployment."""

    @abstractmethod
    def build(self, project_path: str, tag: str) -> str:
        """Build a Docker image from project_path and tag it. Returns build logs."""
        pass

    @abstractmethod
    def run(self, tag: str, name: str, port: int, env_file_path: str | None = None) -> str:
        """Run the container with security flags and port mapping. Returns container run logs."""
        pass

    @abstractmethod
    def stop(self, name: str) -> None:
        """Stop and remove the named container."""
        pass

    @abstractmethod
    def logs(self, name: str) -> str:
        """Fetch container execution logs."""
        pass

    @abstractmethod
    def healthcheck(self, url: str) -> bool:
        """Check if deployment endpoint is responding."""
        pass
