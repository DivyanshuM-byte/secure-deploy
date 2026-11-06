from dataclasses import asdict, dataclass
from typing import Literal

SeverityLevel = Literal["low", "medium", "high", "critical"]


def mask_secret(raw_value: str) -> str:
    """Mask a secret string, showing only the first 4 and last 2 characters."""
    cleaned = raw_value.strip()
    if len(cleaned) <= 6:
        return "****"
    return f"{cleaned[:4]}****{cleaned[-2:]}"


@dataclass
class Finding:
    """Represents a potential secret or sensitive file discovered during a scan."""

    file: str
    line: int
    type: str
    severity: SeverityLevel
    masked_preview: str

    def to_dict(self) -> dict:
        """Convert the finding dataclass into a plain dictionary."""
        return asdict(self)
