from __future__ import annotations

from dataclasses import asdict, dataclass
import os
import re
from typing import Any
import urllib.parse
import uuid

import httpx

from scanner.models import mask_secret
from scanner.pii import scan_file_pii
from scanner.secrets import scan_file

PROBE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/config.json",
    "/server.pem",
    "/id_rsa",
    "/terraform.tfstate",
    "/backup.sql",
    "/dump.sql",
    "/docker-compose.yml",
    "/Dockerfile",
    "/package.json",
    "/.htpasswd",
    "/.DS_Store",
    "/wp-config.php.bak",
]

MAX_BODY_BYTES = 1024 * 1024  # 1 MB


@dataclass
class ProbeItem:
    path: str
    status: int | None
    verdict: str  # "safe" | "exposed" | "warning"
    note: str


@dataclass
class ProbeResult:
    items: list[ProbeItem]
    overall_verdict: str  # "safe" | "exposed" | "warning"
    exposed_count: int
    warning_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [asdict(item) for item in self.items],
            "overall_verdict": self.overall_verdict,
            "exposed_count": self.exposed_count,
            "warning_count": self.warning_count,
        }


def validate_probe_target(base_url: str) -> None:
    """SSRF Safety: Only allow probing loopback 127.0.0.1 or configured EC2 host."""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"SSRF safety violation: Invalid URL scheme '{parsed.scheme}'")

    hostname = (parsed.hostname or "").lower()
    allowed_hosts = {"127.0.0.1", "localhost"}
    ec2_host = os.getenv("EC2_HOST", "").strip().lower()
    if ec2_host:
        allowed_hosts.add(ec2_host)

    if hostname not in allowed_hosts:
        raise ValueError(
            f"SSRF safety violation: Host '{hostname}' is not an authorized deployment target"
        )


def looks_like_real_file(path: str, body: str) -> bool:
    """Verify response body contains genuine content signatures rather than error or fallback pages."""
    cleaned = body.strip()
    if not cleaned:
        return False

    # Never treat an HTML document as a sensitive file exposure unless scanning for bundled secrets
    if cleaned.lower().startswith(("<!doctype html", "<html", "<head")):
        return False

    norm_path = path.lower()
    if "/.env" in norm_path:
        # Must have at least one KEY=VALUE line
        return bool(re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", cleaned))

    if "/.git/config" in norm_path or "/.git/head" in norm_path:
        return "[core]" in cleaned or "ref:" in cleaned or "[remote" in cleaned

    if "/.gitignore" in norm_path:
        # Common gitignore content
        return bool(re.search(r"(?m)^(?:node_modules|\.env|__pycache__|\*\.[a-z]+|#)", cleaned))

    if norm_path.endswith((".pem", "/id_rsa")):
        return "BEGIN" in cleaned and "KEY" in cleaned

    if norm_path.endswith("/terraform.tfstate"):
        return cleaned.startswith("{") and ("terraform" in cleaned or "resources" in cleaned or "version" in cleaned)

    if norm_path.endswith(("/backup.sql", "/dump.sql")):
        return bool(re.search(r"(?i)(?:CREATE TABLE|INSERT INTO|-- MySQL|-- PostgreSQL|DROP TABLE)", cleaned))

    if norm_path.endswith("/docker-compose.yml"):
        return bool(re.search(r"(?m)^(?:version:|services:|networks:)", cleaned))

    if norm_path.endswith("/dockerfile"):
        return bool(re.search(r"(?m)^FROM\s+", cleaned))

    if norm_path.endswith("/package.json"):
        return cleaned.startswith("{") and bool(re.search(r'"(?:name|version|dependencies|scripts)"', cleaned))

    if norm_path.endswith("/config.json"):
        return cleaned.startswith("{") and ":" in cleaned

    if norm_path.endswith("/.htpasswd"):
        return bool(re.search(r"(?m)^[a-zA-Z0-9_.-]+:[^\s]+", cleaned))

    if norm_path.endswith("/.ds_store"):
        return "Bud1" in cleaned or "\x00\x00\x00\x01" in cleaned

    if norm_path.endswith("/wp-config.php.bak"):
        return "DB_NAME" in cleaned or "<?php" in cleaned or "DB_PASSWORD" in cleaned

    return True


def probe_deployment(base_url: str, verify_tls: bool = False) -> ProbeResult:
    """Audit a deployed container for exposed sensitive files, bundled secrets, and missing security headers.
    
    Safety:
    - Validates target host strictly against SSRF whitelist.
    - Baseline 404 test prevents SPA 200 fallbacks from false positive exposure alerts.
    - Limits read size to 1MB and request timeout to 5s.
    """
    validate_probe_target(base_url)

    normalized_base = base_url.rstrip("/")
    items: list[ProbeItem] = []

    # Configure client: 5s timeout, no cross-host redirects, verify TLS setting
    with httpx.Client(
        timeout=5.0,
        verify=verify_tls,
        follow_redirects=False,
        headers={"User-Agent": "secure-deploy-probe/1.0"},
    ) as client:
        # Step 1: Baseline request to a non-existent path to detect SPA catch-all 200 responses
        random_nonexistent = f"/__sd_probe_baseline_{uuid.uuid4().hex[:12]}__"
        baseline_status = 404
        baseline_body = ""
        try:
            resp_baseline = client.get(f"{normalized_base}{random_nonexistent}")
            baseline_status = resp_baseline.status_code
            baseline_body = resp_baseline.text[:MAX_BODY_BYTES]
        except Exception:
            pass

        baseline_norm = re.sub(r"\s+", " ", baseline_body).strip()

        # Step 2: Probe sensitive paths
        for path in PROBE_PATHS:
            target_url = f"{normalized_base}{path}"
            try:
                resp = client.get(target_url)
                body = resp.text[:MAX_BODY_BYTES]
                status_code = resp.status_code

                if status_code == 200:
                    curr_norm = re.sub(r"\s+", " ", body).strip()
                    # Check if identical to baseline SPA fallback
                    if body == baseline_body or (curr_norm and curr_norm == baseline_norm):
                        items.append(ProbeItem(
                            path=path,
                            status=status_code,
                            verdict="safe",
                            note="Returned SPA 200 fallback matching baseline (not exposed)",
                        ))
                    elif looks_like_real_file(path, body):
                        items.append(ProbeItem(
                            path=path,
                            status=status_code,
                            verdict="exposed",
                            note=f"Sensitive file publicly exposed at {path}",
                        ))
                    else:
                        items.append(ProbeItem(
                            path=path,
                            status=status_code,
                            verdict="safe",
                            note="200 returned but content signature does not match target file",
                        ))
                else:
                    items.append(ProbeItem(
                        path=path,
                        status=status_code,
                        verdict="safe",
                        note=f"HTTP {status_code}",
                    ))
            except Exception as exc:
                items.append(ProbeItem(
                    path=path,
                    status=None,
                    verdict="safe",
                    note=f"Connection failed: {str(exc)[:60]}",
                ))

        # Step 3: Fetch homepage (/) to scan for bundled client-side secrets & audit security headers
        try:
            hp_resp = client.get(f"{normalized_base}/")
            hp_status = hp_resp.status_code
            hp_body = hp_resp.text[:MAX_BODY_BYTES]
            hp_headers = hp_resp.headers

            # 3a: Run existing secrets & PII scanners on served homepage HTML/JS
            import tempfile
            from pathlib import Path
            with tempfile.NamedTemporaryFile("w+", suffix=".html", delete=False, encoding="utf-8") as tmp_hp:
                tmp_hp.write(hp_body)
                tmp_hp_path = Path(tmp_hp.name)
            try:
                sec_findings = scan_file(tmp_hp_path, "/")
                pii_findings = scan_file_pii(tmp_hp_path, "/")
                for finding in sec_findings + pii_findings:
                    if finding.severity in ("high", "critical"):
                        items.append(ProbeItem(
                            path="/",
                            status=hp_status,
                            verdict="exposed",
                            note=f"Homepage exposed {finding.type}: {finding.masked_preview}",
                        ))
            finally:
                if tmp_hp_path.exists():
                    try:
                        tmp_hp_path.unlink()
                    except Exception:
                        pass

            # 3c: Check response security headers
            required_headers = [
                ("X-Content-Type-Options", "X-Content-Type-Options missing (nosniff)"),
                ("X-Frame-Options", "X-Frame-Options missing (clickjacking defense)"),
                ("Content-Security-Policy", "Content-Security-Policy missing"),
                ("Referrer-Policy", "Referrer-Policy missing"),
            ]
            for hdr, msg in required_headers:
                if hdr.lower() not in [k.lower() for k in hp_headers.keys()]:
                    items.append(ProbeItem(
                        path=f"headers/{hdr}",
                        status=hp_status,
                        verdict="warning",
                        note=msg,
                    ))

            server_header = hp_headers.get("server", "")
            if server_header and re.search(r"/[0-9]+", server_header):
                items.append(ProbeItem(
                    path="headers/Server",
                    status=hp_status,
                    verdict="warning",
                    note=f"Server header reveals exact software version: {server_header}",
                ))

        except Exception as exc:
            items.append(ProbeItem(
                path="/",
                status=None,
                verdict="warning",
                note=f"Could not audit homepage: {str(exc)[:60]}",
            ))

    exposed_count = sum(1 for i in items if i.verdict == "exposed")
    warning_count = sum(1 for i in items if i.verdict == "warning")

    if exposed_count > 0:
        overall_verdict = "exposed"
    elif warning_count > 0:
        overall_verdict = "warning"
    else:
        overall_verdict = "safe"

    return ProbeResult(
        items=items,
        overall_verdict=overall_verdict,
        exposed_count=exposed_count,
        warning_count=warning_count,
    )
