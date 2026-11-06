from __future__ import annotations

import fnmatch
from pathlib import Path
import os
from .models import Finding, SeverityLevel
from .utils import SKIP_DIRS

# Safe template exclusions
SAFE_TEMPLATES: set[str] = {
    ".env.example",
    ".env.sample",
    ".env.template",
}

# Mapping of file pattern / filename to (finding_type, severity)
SENSITIVE_PATTERNS: list[tuple[str, str, SeverityLevel]] = [
    # Critical keys and states
    ("*.pem", "certificate_or_key_file", "critical"),
    ("*.key", "private_key_file", "critical"),
    ("id_rsa", "ssh_private_key_file", "critical"),
    ("id_ed25519", "ssh_private_key_file", "critical"),
    ("*.pfx", "pkcs12_certificate_file", "critical"),
    ("*.p12", "pkcs12_certificate_file", "critical"),
    ("terraform.tfstate*", "terraform_state_file", "critical"),
    # High risk credentials
    ("credentials.json", "credentials_file", "high"),
    ("service-account*.json", "service_account_key_file", "high"),
    (".htpasswd", "htpasswd_file", "high"),
    # Medium risk database files
    ("*.sqlite", "database_file", "medium"),
    ("*.db", "database_file", "medium"),
]


def check_sensitive_filename(file_name: str, display_path: str) -> Finding | None:
    """Check a single filename against sensitive file rules without reading content."""
    # Check .env and .env.*
    if file_name == ".env" or file_name.startswith(".env."):
        if file_name in SAFE_TEMPLATES or any(file_name.endswith(ext) for ext in [".example", ".sample", ".template"]):
            return None
        return Finding(
            file=display_path,
            line=1,
            type="sensitive_env_file",
            severity="critical",
            masked_preview=f"[sensitive file: {file_name}]",
        )

    # Check pattern list
    for pattern, finding_type, severity in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(file_name, pattern):
            return Finding(
                file=display_path,
                line=1,
                type=finding_type,
                severity=severity,
                masked_preview=f"[sensitive file: {file_name}]",
            )

    return None


def scan_sensitive_files(path: str) -> list[Finding]:
    """Scan a path or directory recursively for exposed sensitive file types by name."""
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    findings: list[Finding] = []

    if root.is_file():
        finding = check_sensitive_filename(root.name, root.name)
        if finding:
            findings.append(finding)
        return findings

    for current_root, dirs, files in os.walk(root, followlinks=False):
        # Check if an exposed .git directory exists in the tree
        if ".git" in dirs:
            git_path = Path(current_root) / ".git"
            try:
                rel_git = git_path.relative_to(root).as_posix()
            except ValueError:
                rel_git = git_path.as_posix()
            findings.append(
                Finding(
                    file=rel_git,
                    line=1,
                    type="committed_git_dir",
                    severity="high",
                    masked_preview="[sensitive file: .git]",
                )
            )

        # Prune ignored directories
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(current_root) / d).is_symlink())

        for filename in sorted(files):
            full_path = Path(current_root) / filename
            if full_path.is_symlink():
                continue
            try:
                rel_path = full_path.relative_to(root).as_posix()
            except ValueError:
                rel_path = full_path.as_posix()

            finding = check_sensitive_filename(filename, rel_path)
            if finding:
                findings.append(finding)

    return findings
