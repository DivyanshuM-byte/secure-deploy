from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from .files import scan_sensitive_files
from .models import Finding
from .pii import scan_pii
from .risk import calculate_risk
from .secrets import scan_directory

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


@dataclass
class ScanResult:
    """Consolidated result of all scanning phases, deduplicated and assessed for risk."""

    findings: list[Finding]
    risk_score: int
    risk_level: str
    status: str  # "passed" or "blocked"
    blocked_reason: str | None
    findings_by_type: dict[str, int]

    def to_dict(self) -> dict:
        """Convert the scan result dataclass into a dictionary."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "status": self.status,
            "blocked_reason": self.blocked_reason,
            "findings_by_type": self.findings_by_type,
        }


def _format_rule_title(rule_type: str) -> str:
    """Format an internal rule identifier into a readable description."""
    special_titles = {
        "aws_access_key": "AWS access key",
        "aws_secret_key": "AWS secret key",
        "google_api_key": "Google API key",
        "stripe_live_key": "Stripe live key",
        "github_token": "GitHub token",
        "jwt_token": "JWT token",
        "private_key_block": "Private key block",
        "generic_secret_assignment": "Hardcoded secret assignment",
        "high_entropy_string": "High-entropy token",
        "committed_env_file": "Committed .env file",
        "sensitive_env_file": "Exposed .env file",
        "committed_git_dir": "Committed .git directory",
        "certificate_or_key_file": "Private certificate/key file",
        "private_key_file": "Private key file",
        "ssh_private_key_file": "SSH private key file",
        "terraform_state_file": "Terraform state file",
        "credentials_file": "Credentials file",
        "service_account_key_file": "Service account key file",
        "database_file": "Database file",
        "email_address": "Exposed email address",
        "indian_mobile_number": "Indian mobile number",
        "aadhaar_number": "Aadhaar number",
        "pan_number": "PAN number",
        "credit_card_number": "Credit card number",
        "connection_string_password": "Connection string password",
    }
    return special_titles.get(rule_type, rule_type.replace("_", " ").capitalize())


def run_all_scans(path: str) -> ScanResult:
    """Execute secrets, PII, and sensitive files scanners, deduplicating findings and calculating risk."""
    target_path = Path(path).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    # Run all three scanners
    secrets_findings = scan_directory(str(target_path))
    pii_findings = scan_pii(str(target_path))
    files_findings = scan_sensitive_files(str(target_path))

    combined = secrets_findings + pii_findings + files_findings

    # Deduplicate findings by (file, line, type)
    seen_keys: set[tuple[str, int, str]] = set()
    deduped: list[Finding] = []

    for f in combined:
        key = (f.file, f.line, f.type)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    # Sort findings: critical -> high -> medium -> low, then by file and line
    deduped.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(x.severity.lower(), 99),
            x.file.lower(),
            x.line,
        )
    )

    # Calculate risk assessment
    risk = calculate_risk(deduped)
    findings_by_type = dict(Counter(f.type for f in deduped))

    # Formulate blocked reason
    blocked_reason: str | None = None
    if risk["status"] == "blocked" and deduped:
        first = deduped[0]
        rule_desc = _format_rule_title(first.type)
        remaining = len(deduped) - 1
        if remaining > 0:
            blocked_reason = f"Blocked: {rule_desc} found in {first.file} line {first.line} (+{remaining} more findings)"
        else:
            blocked_reason = f"Blocked: {rule_desc} found in {first.file} line {first.line}"
    elif risk["status"] == "blocked":
        blocked_reason = f"Blocked: Risk score threshold reached ({risk['score']}/100)"

    return ScanResult(
        findings=deduped,
        risk_score=risk["score"],
        risk_level=risk["level"],
        status=risk["status"],
        blocked_reason=blocked_reason,
        findings_by_type=findings_by_type,
    )
