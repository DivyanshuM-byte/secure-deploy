from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Literal
import uuid
import zipfile

# pyrefly: ignore [missing-import]
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, Response, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from db import FindingRecord, ScanRecord, SessionLocal, get_db
from scanner.engine import _format_rule_title, run_all_scans

router = APIRouter(prefix="/api/scans", tags=["scans"])

RATE_LIMIT_WINDOW_SECONDS: float = 60.0
MAX_SCANS_PER_MINUTE: int = 10
_ip_scan_timestamps: dict[str, list[float]] = defaultdict(list)

MAX_ZIP_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB
MAX_ZIP_FILES: int = 5000  # Max 5,000 files
MAX_UNCOMPRESSED_BYTES: int = 100 * 1024 * 1024  # 100 MB

GITHUB_URL_REGEX: re.Pattern[str] = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?$"
)


def reset_rate_limits() -> None:
    """Clear in-memory rate limits (primarily for testing suites)."""
    _ip_scan_timestamps.clear()


def enforce_rate_limit(request: Request) -> None:
    """Enforce max 10 scans per minute per client IP."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    valid_window = now - RATE_LIMIT_WINDOW_SECONDS

    timestamps = [t for t in _ip_scan_timestamps[client_ip] if t > valid_window]
    if len(timestamps) >= MAX_SCANS_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded: max 10 scans per minute.",
        )

    timestamps.append(now)
    _ip_scan_timestamps[client_ip] = timestamps


def get_allowed_roots() -> list[Path]:
    """Return all allowed directory roots for scanning, enforcing path isolation."""
    configured_ws = Path(os.getenv("WORKSPACE_ROOT", "./workspace")).resolve()
    configured_ws.mkdir(parents=True, exist_ok=True)

    base_repo = Path(__file__).resolve().parent.parent.parent
    sample_repos_dir = (base_repo / "tests" / "sample-repos").resolve()
    cwd_sample_repos = Path("tests/sample-repos").resolve()

    return [configured_ws, sample_repos_dir, cwd_sample_repos]


def validate_scan_path(raw_path: str) -> Path:
    """Resolve and validate that the requested path is strictly within an allowed root."""
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        resolved = candidate.resolve()
        if not resolved.exists():
            alt = (Path(__file__).resolve().parent.parent.parent / raw_path).resolve()
            if alt.exists():
                resolved = alt
    else:
        resolved = candidate.resolve()

    if not resolved.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Path does not exist: {raw_path}",
        )

    allowed_roots = get_allowed_roots()
    is_safe = False
    for root in allowed_roots:
        if resolved == root or root in resolved.parents:
            is_safe = True
            break

    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Path traversal rejected: '{raw_path}' is outside allowed workspace root.",
        )

    return resolved


class ScanRequest(BaseModel):
    path: str = Field(..., min_length=1, description="Local directory path to scan")
    sync: bool = Field(True, description="Run synchronously if requested")


class GithubScanRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository HTTPS URL")
    branch: str | None = Field(None, description="Optional branch or tag")


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    file: str
    line: int
    type: str
    severity: str
    masked_preview: str


class ScanSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    status: Literal["queued", "running", "passed", "blocked", "failed"]
    risk_score: int
    risk_level: str
    created_at: datetime
    findings_count: int


class ScanDetailOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    status: Literal["queued", "running", "passed", "blocked", "failed"]
    risk_score: int
    risk_level: str
    created_at: datetime
    blocked_reason: str | None = None
    findings_by_type: dict[str, int]
    findings: list[FindingOut]


class StatsOut(BaseModel):
    total_scans: int
    blocked_count: int
    passed_count: int
    total_findings: int
    findings_by_severity: dict[str, int]
    avg_risk_score: float


class SnippetScanRequest(BaseModel):
    content: str = Field(..., description="Snippet content to scan")
    filename: str = Field("snippet.txt", description="Optional filename for snippet")


class SnippetFindingOut(BaseModel):
    file: str
    line: int
    type: str
    severity: str
    masked_preview: str


class SnippetScanOut(BaseModel):
    findings: list[SnippetFindingOut]
    risk_score: int
    risk_level: str
    status: Literal["passed", "blocked"]
    blocked_reason: str | None = None


def build_blocked_reason(status_str: str, findings: list) -> str | None:
    if status_str != "blocked" or not findings:
        return None
    first = findings[0]
    first_type = getattr(first, "type", first.get("type") if isinstance(first, dict) else "")
    first_file = getattr(first, "file", first.get("file") if isinstance(first, dict) else "")
    first_line = getattr(first, "line", first.get("line") if isinstance(first, dict) else 1)
    rule_title = _format_rule_title(first_type)
    remaining = len(findings) - 1
    if remaining > 0:
        return f"Blocked: {rule_title} found in {first_file} line {first_line} (+{remaining} more findings)"
    return f"Blocked: {rule_title} found in {first_file} line {first_line}"


def process_scan_task(scan_id: int, target_path: str, cleanup_dir: str | None = None) -> None:
    """Background task to run scanners and persist results in SQLite."""
    db = SessionLocal()
    try:
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if not scan:
            return
        scan.status = "running"
        db.commit()

        scan_result = run_all_scans(target_path)

        scan.status = scan_result.status
        scan.risk_score = scan_result.risk_score
        scan.risk_level = scan_result.risk_level
        scan.blocked_reason = scan_result.blocked_reason

        for item in scan_result.findings:
            fr = FindingRecord(
                scan_id=scan.id,
                file=item.file,
                line=item.line,
                type=item.type,
                severity=item.severity,
                masked_preview=item.masked_preview,
            )
            db.add(fr)

        db.commit()

        # Day 4: Save approved source code for passed scans only
        if scan.status == "passed":
            configured_ws = Path(os.getenv("WORKSPACE_ROOT", "./workspace")).resolve()
            approved_dir = configured_ws / "approved" / str(scan.id)
            approved_dir.parent.mkdir(parents=True, exist_ok=True)
            if os.path.exists(target_path):
                shutil.copytree(target_path, approved_dir, dirs_exist_ok=True)
    except Exception as exc:
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.blocked_reason = f"Scan failed: {str(exc)}"
            db.commit()
    finally:
        db.close()
        if cleanup_dir and os.path.exists(cleanup_dir):
            shutil.rmtree(cleanup_dir, ignore_errors=True)


def get_git_clone_timeout() -> int:
    """Retrieve Git clone timeout from GIT_CLONE_TIMEOUT_SECONDS env var.
    Default is 120 seconds; allowed range is 30 to 600 seconds.
    """
    raw_val = os.getenv("GIT_CLONE_TIMEOUT_SECONDS", "120")
    try:
        val = int(raw_val)
        if 30 <= val <= 600:
            return val
    except (ValueError, TypeError):
        pass
    return 120


def clone_and_scan_github_task(scan_id: int, repo_url: str, branch: str | None) -> None:
    """Background task to clone a remote GitHub repository and scan it."""
    db = SessionLocal()
    configured_ws = Path(os.getenv("WORKSPACE_ROOT", "./workspace")).resolve()
    clone_dir = configured_ws / "github" / str(uuid.uuid4())
    clone_dir.parent.mkdir(parents=True, exist_ok=True)
    clone_timeout = get_git_clone_timeout()
    try:
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if not scan:
            return
        scan.status = "running"
        db.commit()

        cmd = ["git", "clone", "--depth", "1", "--single-branch"]
        if branch:
            cmd.extend(["-b", branch])
        cmd.extend([repo_url, str(clone_dir)])

        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "echo",
        }

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=clone_timeout, env=env)
        if proc.returncode != 0:
            scan.status = "failed"
            err_msg = proc.stderr.strip() or "Repository not found or private."
            scan.blocked_reason = f"Clone failed: {err_msg}"
            db.commit()
            return

        scan_result = run_all_scans(str(clone_dir))

        scan.status = scan_result.status
        scan.risk_score = scan_result.risk_score
        scan.risk_level = scan_result.risk_level
        scan.blocked_reason = scan_result.blocked_reason

        for item in scan_result.findings:
            fr = FindingRecord(
                scan_id=scan.id,
                file=item.file,
                line=item.line,
                type=item.type,
                severity=item.severity,
                masked_preview=item.masked_preview,
            )
            db.add(fr)

        db.commit()

        # Day 4: Save approved source code for passed scans only
        if scan.status == "passed":
            configured_ws = Path(os.getenv("WORKSPACE_ROOT", "./workspace")).resolve()
            approved_dir = configured_ws / "approved" / str(scan.id)
            approved_dir.parent.mkdir(parents=True, exist_ok=True)
            if clone_dir.exists():
                shutil.copytree(clone_dir, approved_dir, dirs_exist_ok=True)
    except subprocess.TimeoutExpired:
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.blocked_reason = (
                f"Git clone timed out after {clone_timeout} seconds. "
                "The repository may be too large; try a smaller repo or increase GIT_CLONE_TIMEOUT_SECONDS."
            )
            db.commit()
    except Exception as exc:
        scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.blocked_reason = f"Scan error: {str(exc)}"
            db.commit()
    finally:
        db.close()
        if clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)


@router.post("", response_model=ScanDetailOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> dict:
    """Initiate a scan for a local workspace directory path."""
    enforce_rate_limit(request)
    resolved_path = validate_scan_path(payload.path)

    # If payload explicitly requests sync execution, execute immediately
    if payload.sync:
        scan_result = run_all_scans(str(resolved_path))
        scan_record = ScanRecord(
            source=payload.path,
            status=scan_result.status,
            risk_score=scan_result.risk_score,
            risk_level=scan_result.risk_level,
            blocked_reason=scan_result.blocked_reason,
        )
        db.add(scan_record)
        db.flush()

        finding_records = []
        for item in scan_result.findings:
            fr = FindingRecord(
                scan_id=scan_record.id,
                file=item.file,
                line=item.line,
                type=item.type,
                severity=item.severity,
                masked_preview=item.masked_preview,
            )
            db.add(fr)
            finding_records.append(fr)

        db.commit()
        db.refresh(scan_record)

        return {
            "id": scan_record.id,
            "source": scan_record.source,
            "status": scan_record.status,
            "risk_score": scan_record.risk_score,
            "risk_level": scan_record.risk_level,
            "created_at": scan_record.created_at,
            "blocked_reason": scan_record.blocked_reason,
            "findings_by_type": scan_result.findings_by_type,
            "findings": finding_records,
        }

    # Default Day 3 async mode: return immediately with status queued
    scan_record = ScanRecord(
        source=payload.path,
        status="queued",
        risk_score=0,
        risk_level="low",
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    background_tasks.add_task(process_scan_task, scan_record.id, str(resolved_path), None)

    return {
        "id": scan_record.id,
        "source": scan_record.source,
        "status": "queued",
        "risk_score": 0,
        "risk_level": "low",
        "created_at": scan_record.created_at,
        "blocked_reason": None,
        "findings_by_type": {},
        "findings": [],
    }


@router.post("/upload", response_model=ScanDetailOut, status_code=status.HTTP_201_CREATED)
async def upload_zip_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict:
    """Accept and scan an uploaded zip file with zip-slip, zip bomb, and symlink protection."""
    enforce_rate_limit(request)

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .zip files are accepted.",
        )

    content = await file.read()
    if len(content) > MAX_ZIP_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ZIP file exceeds maximum allowed size of 25 MB.",
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or corrupted ZIP archive.",
        ) from exc

    infolist = zf.infolist()
    if len(infolist) > MAX_ZIP_FILES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ZIP archive contains {len(infolist)} files, exceeding limit of {MAX_ZIP_FILES}.",
        )

    total_uncompressed = sum(info.file_size for info in infolist)
    if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Uncompressed size exceeds 100 MB limit ({total_uncompressed / (1024 * 1024):.1f} MB).",
        )

    configured_ws = Path(os.getenv("WORKSPACE_ROOT", "./workspace")).resolve()
    upload_id = str(uuid.uuid4())
    extract_dir = configured_ws / "uploads" / upload_id
    extract_dir.mkdir(parents=True, exist_ok=True)

    # Validate against zip-slip and prohibited symlinks
    for info in infolist:
        is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
        if is_symlink:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Prohibited symlink entry detected in ZIP: {info.filename}",
            )

        target_path = (extract_dir / info.filename).resolve()
        if not target_path.is_relative_to(extract_dir.resolve()):
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Zip-slip path traversal rejected: {info.filename}",
            )

    try:
        zf.extractall(extract_dir)
    except Exception as exc:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to extract ZIP: {str(exc)}",
        ) from exc

    scan_record = ScanRecord(
        source=f"upload:{file.filename}",
        status="queued",
        risk_score=0,
        risk_level="low",
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    background_tasks.add_task(process_scan_task, scan_record.id, str(extract_dir), str(extract_dir))

    return {
        "id": scan_record.id,
        "source": scan_record.source,
        "status": "queued",
        "risk_score": 0,
        "risk_level": "low",
        "created_at": scan_record.created_at,
        "blocked_reason": None,
        "findings_by_type": {},
        "findings": [],
    }


@router.post("/github", response_model=ScanDetailOut, status_code=status.HTTP_201_CREATED)
def scan_github_repo(
    payload: GithubScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> dict:
    """Clone and scan a public GitHub repository."""
    enforce_rate_limit(request)

    repo_url = payload.repo_url.strip()
    if not GITHUB_URL_REGEX.match(repo_url) or any(c in repo_url for c in ";|&$`<>\\"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid GitHub repository URL. Must be in format https://github.com/owner/repo",
        )

    if payload.branch and any(c in payload.branch for c in ";|&$`<>\\ \t"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid branch name format.",
        )

    scan_record = ScanRecord(
        source=f"github:{repo_url}",
        status="queued",
        risk_score=0,
        risk_level="low",
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    background_tasks.add_task(
        clone_and_scan_github_task,
        scan_record.id,
        repo_url,
        payload.branch,
    )

    return {
        "id": scan_record.id,
        "source": scan_record.source,
        "status": "queued",
        "risk_score": 0,
        "risk_level": "low",
        "created_at": scan_record.created_at,
        "blocked_reason": None,
        "findings_by_type": {},
        "findings": [],
    }


@router.post("/snippet", response_model=SnippetScanOut)
def scan_snippet(
    payload: SnippetScanRequest,
    request: Request,
) -> dict:
    """Scan an ephemeral code snippet without persisting to database or logging content."""
    enforce_rate_limit(request)

    content_bytes = payload.content.encode("utf-8")
    if len(content_bytes) > 100 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Snippet exceeds maximum allowed size of 100 KB.",
        )

    raw_basename = Path(payload.filename).name
    sanitized_name = re.sub(r"[^a-zA-Z0-9._-]", "", raw_basename)
    if not sanitized_name or sanitized_name in {".", ".."}:
        sanitized_name = "snippet.txt"

    temp_dir = tempfile.mkdtemp(prefix="secure_deploy_snippet_")
    try:
        snippet_file = Path(temp_dir) / sanitized_name
        snippet_file.write_text(payload.content, encoding="utf-8")

        scan_result = run_all_scans(temp_dir)

        findings = [
            {
                "file": sanitized_name,
                "line": f.line,
                "type": f.type,
                "severity": f.severity,
                "masked_preview": f.masked_preview,
            }
            for f in scan_result.findings
        ]

        return {
            "findings": findings,
            "risk_score": scan_result.risk_score,
            "risk_level": scan_result.risk_level,
            "status": scan_result.status,
            "blocked_reason": scan_result.blocked_reason,
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("", response_model=list[ScanSummaryOut])
def list_scans(db: Session = Depends(get_db)) -> list[dict]:
    """List all scans ordered from newest to oldest."""
    scans = db.query(ScanRecord).order_by(ScanRecord.id.desc()).all()
    return [
        {
            "id": scan.id,
            "source": scan.source,
            "status": scan.status,
            "risk_score": getattr(scan, "risk_score", 0) or 0,
            "risk_level": getattr(scan, "risk_level", "low") or "low",
            "created_at": scan.created_at,
            "findings_count": len(scan.findings),
        }
        for scan in scans
    ]


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> dict:
    """Retrieve a single scan by ID including findings, risk breakdown, and blocked reason."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    findings_by_type = dict(Counter(f.type for f in scan.findings))
    blocked_reason = scan.blocked_reason or build_blocked_reason(scan.status, scan.findings)

    return {
        "id": scan.id,
        "source": scan.source,
        "status": scan.status,
        "risk_score": getattr(scan, "risk_score", 0) or 0,
        "risk_level": getattr(scan, "risk_level", "low") or "low",
        "created_at": scan.created_at,
        "blocked_reason": blocked_reason,
        "findings_by_type": findings_by_type,
        "findings": scan.findings,
    }


@router.get("/{scan_id}/report")
def get_scan_report(scan_id: int, db: Session = Depends(get_db)) -> Response:
    """Download full scan report as a JSON file attachment with masked previews only."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    findings_out = [
        {
            "id": f.id,
            "file": f.file,
            "line": f.line,
            "type": f.type,
            "severity": f.severity,
            "masked_preview": f.masked_preview,
        }
        for f in scan.findings
    ]

    report = {
        "scan_id": scan.id,
        "source": scan.source,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "created_at": scan.created_at.isoformat(),
        "blocked_reason": scan.blocked_reason or build_blocked_reason(scan.status, scan.findings),
        "total_findings": len(findings_out),
        "findings_by_type": dict(Counter(f["type"] for f in findings_out)),
        "findings": findings_out,
    }

    report_json = json.dumps(report, indent=2)
    return Response(
        content=report_json,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id}-report.json"'
        },
    )


def calculate_platform_stats(db: Session) -> dict:
    """Calculate aggregate platform statistics."""
    total_scans = db.query(ScanRecord).count()
    blocked_count = db.query(ScanRecord).filter(ScanRecord.status == "blocked").count()
    passed_count = db.query(ScanRecord).filter(ScanRecord.status == "passed").count()

    findings = db.query(FindingRecord).all()
    total_findings = len(findings)

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    completed_scans = (
        db.query(ScanRecord)
        .filter(ScanRecord.status.in_(["passed", "blocked"]))
        .all()
    )
    if completed_scans:
        avg_risk_score = round(
            sum(s.risk_score for s in completed_scans) / len(completed_scans), 1
        )
    else:
        avg_risk_score = 0.0

    return {
        "total_scans": total_scans,
        "blocked_count": blocked_count,
        "passed_count": passed_count,
        "total_findings": total_findings,
        "findings_by_severity": severity_counts,
        "avg_risk_score": avg_risk_score,
    }
