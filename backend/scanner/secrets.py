import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Pattern

from .models import Finding, SeverityLevel, mask_secret
from .utils import MAX_FILE_SIZE_BYTES, SKIP_DIRS, is_binary_file

ENTROPY_THRESHOLD: float = 4.2
MIN_ENTROPY_STRING_LENGTH: int = 20

# Easy-to-extend dictionary of secret detection rules.
# Maps rule_name -> (compiled_regex, severity, group_index_for_secret)
SECRET_PATTERNS: dict[str, tuple[Pattern[str], SeverityLevel, int]] = {
    "aws_access_key": (
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "critical",
        1,
    ),
    "aws_secret_key": (
        re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        "critical",
        1,
    ),
    "google_api_key": (
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "high",
        1,
    ),
    "stripe_live_key": (
        re.compile(r"\b(sk_(?:live|local)_[0-9a-zA-Z]{24,})\b"),
        "critical",
        1,
    ),
    "github_token": (
        re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
        "high",
        1,
    ),
    "jwt_token": (
        re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
        "high",
        1,
    ),
    "private_key_block": (
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        "critical",
        1,
    ),
    "generic_secret_assignment": (
        re.compile(
            r"(?i)\b[a-z0-9_]*(?:api_key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\r\n]{8,})['\"]"
        ),
        "high",
        1,
    ),
}

QUOTED_STRING_PATTERN: Pattern[str] = re.compile(r"['\"]([^'\"\r\n]{21,})['\"]")


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy (in bits per character) of a string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_binary_file(file_path: Path) -> bool:
    """Return True if the file appears to be binary by checking for null bytes."""
    try:
        with file_path.open("rb") as f:
            chunk = f.read(4096)
        return b"\x00" in chunk
    except OSError:
        return True


UUID_REGEX: Pattern[str] = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_HASH_REGEX: Pattern[str] = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _looks_like_non_secret_literal(candidate: str) -> bool:
    """Filter out common high-length non-secret strings such as URLs, paths, UUIDs, hashes, or prose."""
    if " " in candidate or "\t" in candidate:
        return True
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://", "postgres://", "sqlite://", "data:", "/", "./", "../")):
        return True
    if candidate.startswith("iVBORw0KGgo"):
        return True
    if UUID_REGEX.match(candidate):
        return True
    if HEX_HASH_REGEX.match(candidate):
        return True
    # Must contain a mix of character classes to be a high-entropy secret token
    has_lower = any(c.islower() for c in candidate)
    has_upper = any(c.isupper() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    return not ((has_lower and has_digit) or (has_upper and has_digit) or (has_lower and has_upper))


def scan_file(file_path: Path, display_path: str) -> list[Finding]:
    """Scan a single file for committed .env exposure, regex secret patterns, and high-entropy strings."""
    findings: list[Finding] = []

    # Flag committed .env files immediately as critical
    if file_path.name == ".env" or (
        file_path.name.startswith(".env.")
        and file_path.name not in {".env.example", ".env.sample", ".env.template"}
    ):
        findings.append(
            Finding(
                file=display_path,
                line=1,
                type="committed_env_file",
                severity="critical",
                masked_preview=mask_secret(f"ENV_FILE_{file_path.name}"),
            )
        )

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
        matched_spans: list[tuple[int, int]] = []
        matched_values: set[str] = set()

        for rule_name, (pattern, severity, group_idx) in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                secret_value = match.group(group_idx)
                # Avoid duplicate generic_secret_assignment if a specific provider pattern already matched
                if rule_name == "generic_secret_assignment" and secret_value in matched_values:
                    continue

                matched_values.add(secret_value)
                matched_spans.append(match.span(group_idx))
                findings.append(
                    Finding(
                        file=display_path,
                        line=line_number,
                        type=rule_name,
                        severity=severity,
                        masked_preview=mask_secret(secret_value),
                    )
                )

        # Check quoted strings > 20 chars for high Shannon entropy
        for quoted_match in QUOTED_STRING_PATTERN.finditer(line):
            candidate = quoted_match.group(1)
            q_start, q_end = quoted_match.span(1)

            if len(candidate) <= MIN_ENTROPY_STRING_LENGTH:
                continue

            # Skip if already captured by a specific regex pattern on this line
            if candidate in matched_values or any(
                not (q_end <= s_start or q_start >= s_end) for s_start, s_end in matched_spans
            ):
                continue

            if _looks_like_non_secret_literal(candidate):
                continue

            entropy = calculate_shannon_entropy(candidate)
            if entropy >= ENTROPY_THRESHOLD:
                findings.append(
                    Finding(
                        file=display_path,
                        line=line_number,
                        type="high_entropy_string",
                        severity="medium",
                        masked_preview=mask_secret(candidate),
                    )
                )

    return findings


def scan_directory(path: str) -> list[Finding]:
    """Recursively scan a directory or single file path and return all detected findings."""
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    if root.is_file():
        return scan_file(root, root.name)

    all_findings: list[Finding] = []

    for current_root, dirs, files in os.walk(root, followlinks=False):
        # Prune ignored directories in-place so os.walk never descends into them
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(current_root) / d).is_symlink())

        for filename in sorted(files):
            full_path = Path(current_root) / filename
            if full_path.is_symlink():
                continue
            try:
                rel_path = full_path.relative_to(root).as_posix()
            except ValueError:
                rel_path = full_path.as_posix()

            all_findings.extend(scan_file(full_path, rel_path))

    return all_findings
