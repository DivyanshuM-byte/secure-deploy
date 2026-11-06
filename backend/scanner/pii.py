import os
import re
from pathlib import Path
from typing import Pattern

from .models import Finding, SeverityLevel, mask_secret
from .utils import (
    MAX_FILE_SIZE_BYTES,
    SKIP_DIRS,
    is_binary_file,
    validate_luhn,
    validate_verhoeff,
)

# Common dummy / safe allow-lists to eliminate false positives
DUMMY_EMAIL_DOMAINS: set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.org",
    "sample.com",
    "localhost",
    "domain.com",
}

DUMMY_EMAILS: set[str] = {
    "test@test.com",
    "user@example.com",
    "admin@example.com",
    "john.doe@example.com",
}

DUMMY_PHONE_NUMBERS: set[str] = {
    "1234567890",
    "0123456789",
    "9876500000",
}

DUMMY_CONNECTION_PASSWORDS: set[str] = {
    "password",
    "pass",
    "secret",
    "dummy",
    "test",
    "changeme",
    "none",
    "null",
}

# Regex patterns for initial PII candidate extraction
EMAIL_PATTERN: Pattern[str] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Indian mobile: 10 digits starting with 6-9, optional +91 or 0 prefix, optional hyphen/space
INDIAN_MOBILE_PATTERN: Pattern[str] = re.compile(
    r"(?:(?:\+91[\-\s]?|0)?\b([6-9]\d{4}[\-\s]?\d{5})\b)"
)

# Aadhaar: 12 digits, typically grouped in 4s, starting with 2-9, not adjacent to hyphen or alnum
AADHAAR_PATTERN: Pattern[str] = re.compile(
    r"(?<![-A-Za-z0-9])([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})(?![-A-Za-z0-9])"
)

# Permanent Account Number (PAN): 5 letters, 4 digits, 1 letter
PAN_PATTERN: Pattern[str] = re.compile(
    r"\b([A-Z]{5}[0-9]{4}[A-Z])\b"
)

# Credit card: 13-19 digits, possibly with space or dash grouping
CREDIT_CARD_PATTERN: Pattern[str] = re.compile(
    r"\b(?:\d{4}[\s\-]){3}\d{1,7}\b|\b\d{13,19}\b"
)

# Database connection strings with embedded passwords
CONNECTION_STRING_PATTERN: Pattern[str] = re.compile(
    r"(?i)\b(?:postgres|postgresql|mysql|mariadb|mongodb|redis|amqp|mssql):\/\/(?:[^:\s\/]+):([^@\s\/\r\n]+)@[^\s]+"
)


def _is_dummy_email(email: str) -> bool:
    """Return True if email matches test or placeholder domain."""
    lowered = email.lower()
    if lowered in DUMMY_EMAILS:
        return True
    domain = lowered.split("@")[-1]
    return domain in DUMMY_EMAIL_DOMAINS or domain.endswith(".example.com")


def _is_dummy_phone(phone_digits: str) -> bool:
    """Return True if phone number is a sequence or repeated digit dummy."""
    if phone_digits in DUMMY_PHONE_NUMBERS:
        return True
    if len(set(phone_digits)) == 1:
        return True
    if phone_digits == "1234567890":
        return True
    return False


def scan_file_pii(file_path: Path, display_path: str) -> list[Finding]:
    """Scan a single file for PII and return findings with masked previews."""
    findings: list[Finding] = []

    try:
        if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return findings
    except OSError:
        return findings

    if is_binary_file(file_path):
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for line_number, line in enumerate(content.splitlines(), start=1):
        # 1. Connection string passwords
        for match in CONNECTION_STRING_PATTERN.finditer(line):
            password = match.group(1)
            if password.lower() not in DUMMY_CONNECTION_PASSWORDS and len(password) >= 3:
                findings.append(
                    Finding(
                        file=display_path,
                        line=line_number,
                        type="connection_string_password",
                        severity="high",
                        masked_preview=mask_secret(password),
                    )
                )

        # 2. Aadhaar numbers (12 digits, Verhoeff checksum)
        for match in AADHAAR_PATTERN.finditer(line):
            candidate = match.group(1)
            digits = "".join(c for c in candidate if c.isdigit())
            if len(digits) == 12 and len(set(digits)) > 1:
                if digits not in {"000000000000", "111111111111"} and validate_verhoeff(digits):
                    findings.append(
                        Finding(
                            file=display_path,
                            line=line_number,
                            type="aadhaar_number",
                            severity="critical",
                            masked_preview=mask_secret(digits),
                        )
                    )

        # 3. Credit card numbers (13-19 digits, Luhn checksum)
        for match in CREDIT_CARD_PATTERN.finditer(line):
            candidate = match.group(0)
            digits = "".join(c for c in candidate if c.isdigit())
            # Ensure it is not an Aadhaar match already handled
            if len(digits) == 12:
                continue
            if 13 <= len(digits) <= 19 and validate_luhn(digits):
                findings.append(
                    Finding(
                        file=display_path,
                        line=line_number,
                        type="credit_card_number",
                        severity="critical",
                        masked_preview=mask_secret(digits),
                    )
                )

        # 4. PAN numbers (5 letters, 4 digits, 1 letter)
        for match in PAN_PATTERN.finditer(line):
            pan_val = match.group(1)
            # Avoid dummy sequences like AAAAA0000A
            if not pan_val.endswith("0000A"):
                findings.append(
                    Finding(
                        file=display_path,
                        line=line_number,
                        type="pan_number",
                        severity="high",
                        masked_preview=mask_secret(pan_val),
                    )
                )

        # 5. Email addresses
        for match in EMAIL_PATTERN.finditer(line):
            email = match.group(0)
            # Skip if match is part of a URL authority (e.g. postgres://user:pass@host)
            prefix = line[:match.start()]
            if "://" in prefix:
                continue
            if not _is_dummy_email(email):
                findings.append(
                    Finding(
                        file=display_path,
                        line=line_number,
                        type="email_address",
                        severity="medium",
                        masked_preview=mask_secret(email),
                    )
                )

        # 6. Indian mobile numbers
        for match in INDIAN_MOBILE_PATTERN.finditer(line):
            raw_match = match.group(1)
            clean_digits = "".join(c for c in raw_match if c.isdigit())
            if len(clean_digits) == 10 and not _is_dummy_phone(clean_digits):
                findings.append(
                    Finding(
                        file=display_path,
                        line=line_number,
                        type="indian_mobile_number",
                        severity="medium",
                        masked_preview=mask_secret(clean_digits),
                    )
                )

    return findings


def scan_pii(path: str) -> list[Finding]:
    """Recursively scan a directory or file for PII while ignoring non-code and oversized files."""
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    if root.is_file():
        return scan_file_pii(root, root.name)

    all_findings: list[Finding] = []

    for current_root, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(current_root) / d).is_symlink())

        for filename in sorted(files):
            full_path = Path(current_root) / filename
            if full_path.is_symlink():
                continue
            try:
                rel_path = full_path.relative_to(root).as_posix()
            except ValueError:
                rel_path = full_path.as_posix()

            all_findings.extend(scan_file_pii(full_path, rel_path))

    return all_findings
