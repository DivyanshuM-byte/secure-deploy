"""Realistic production module with ZERO secrets or PII.

Contains common false-positive traps (git commit SHAs, UUIDs, data URIs, lorem ipsum, example emails).
"""
import uuid


class HealthService:
    """Service to track system health and telemetry identifiers."""

    # False-positive trap 1: Git commit hash (hexadecimal)
    BUILD_COMMIT_SHA: str = "d3b07384d113edec49eaa6238ad5ff00abc12345"

    # False-positive trap 2: Standard UUID
    SYSTEM_INSTANCE_ID: str = "123e4567-e89b-12d3-a456-426614174000"

    # False-positive trap 3: Inline base64 transparent 1x1 image asset
    FAVICON_BASE64: str = (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    )

    # False-positive trap 4: Safe documentation emails
    DOCS_CONTACT: str = "developer-relations@example.com"
    SUPPORT_EMAIL: str = "support@example.org"
    SECURITY_CONTACT: str = "test@test.com"

    # False-positive trap 5: Standard prose / documentation text
    TERMS_SUMMARY: str = (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
        "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, "
        "quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
    )

    def generate_trace_id(self) -> str:
        """Return a newly minted UUID string for tracing."""
        return str(uuid.uuid4())

    def get_version_info(self) -> dict[str, str]:
        """Return build metadata."""
        return {
            "version": "1.4.0",
            "commit": self.BUILD_COMMIT_SHA,
            "instance": self.SYSTEM_INSTANCE_ID,
            "docs": self.DOCS_CONTACT,
        }
