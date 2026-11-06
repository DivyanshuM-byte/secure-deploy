from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Literal
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from db import DeploymentRecord, ProbeResultRecord, ScanRecord, SessionLocal, allocate_next_port, get_db
from deployer.docker_build import (
    ensure_dockerignore,
    generate_dockerfile,
    lint_dockerfile,
    sanitize_identifier,
)
from deployer.ec2 import EC2Deployer
from deployer.local import LocalDockerDeployer
from deployer.probe import probe_deployment
from scanner.engine import run_all_scans
from secrets_store import get_secrets_store, validate_project_slug

router = APIRouter(prefix="/api", tags=["deployments"])

MAX_LOGS_LENGTH = 20 * 1024  # 20 KB


def get_deployer():
    """Factory to retrieve the selected deployer instance from DEPLOY_TARGET environment."""
    target = os.getenv("DEPLOY_TARGET", "local").strip().lower()
    if target == "ec2":
        return EC2Deployer()
    return LocalDockerDeployer()


class DeployRequest(BaseModel):
    project: str | None = None


class DeploymentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    project: str | None = None
    status: Literal["pending", "building", "deploying", "probing", "deployed", "exposed", "failed", "stopped"]
    image_tag: str
    container_name: str
    port: int | None
    url: str | None
    host_type: str
    logs: str
    created_at: datetime
    finished_at: datetime | None = None


def sanitize_logs(raw: str, secret_values: list[str] | None = None) -> str:
    """Sanitize secrets, tokens, passwords, private keys, environment variables, and injected secrets from deploy logs."""
    cleaned = raw

    # Redact injected secret values and their base64 representations
    if secret_values:
        for val in secret_values:
            if val:
                cleaned = cleaned.replace(val, "****")
                try:
                    b64_val = base64.b64encode(val.encode("utf-8")).decode("utf-8")
                    if b64_val:
                        cleaned = cleaned.replace(b64_val, "****")
                except Exception:
                    pass

    # Mask private keys
    cleaned = re.sub(
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        cleaned,
    )
    # Mask database connection string passwords (e.g. postgres://user:password@host)
    cleaned = re.sub(r"(://[^:\s]+):([^@\s]+)@", r"\1:[REDACTED_SECRET]@", cleaned)
    # Strip AWS access keys & Stripe live keys
    cleaned = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA****************", cleaned)
    cleaned = re.sub(r"sk_live_[0-9a-zA-Z]{24,}", "sk_live_********************", cleaned)
    # Strip env vars with secret/key/token/password values
    cleaned = re.sub(
        r"(?i)([\w]*(?:password|secret|token|key|api_key|credential|auth)[\w]*)\s*[:=]\s*['\"]?[^\s'\"]+",
        r"\1=[REDACTED_SECRET]",
        cleaned,
    )
    if len(cleaned) > MAX_LOGS_LENGTH:
        return cleaned[:MAX_LOGS_LENGTH] + "\n... [Logs truncated at 20KB limit]"
    return cleaned


def execute_deployment_task(deployment_id: int, project_path: str, project_slug: str | None = None) -> None:
    """Background task to lint Dockerfile, re-scan files, build Docker image, run container with runtime secrets, and execute post-deploy probe."""
    db = SessionLocal()
    proj_dir = Path(project_path)
    secret_vals: list[str] = []
    env_file_path: str | None = None
    env_temp_dir: str | None = None

    try:
        deployment = db.query(DeploymentRecord).filter(DeploymentRecord.id == deployment_id).first()
        if not deployment:
            return

        deployment.status = "building"
        db.commit()

        # Load project secrets if project slug was supplied
        if project_slug:
            try:
                store = get_secrets_store()
                secrets_dict = store.get_all(project_slug)
                if secrets_dict:
                    secret_vals = list(secrets_dict.values())
                    env_temp_dir = tempfile.mkdtemp(prefix="sd_env_")
                    env_file_path = os.path.join(env_temp_dir, f"{deployment.container_name}.env")
                    fd = os.open(env_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with open(fd, "w", encoding="utf-8") as f:
                        for k, v in secrets_dict.items():
                            f.write(f"{k}={v}\n")
                    os.chmod(env_file_path, 0o600)
            except Exception as sec_err:
                deployment.status = "failed"
                deployment.logs = sanitize_logs(
                    f"Deployment aborted: Failed to resolve secrets for project '{project_slug}': {str(sec_err)}",
                    secret_vals,
                )
                deployment.finished_at = datetime.now(timezone.utc)
                db.commit()
                return

        # Step 1: Re-scan approved directory right before building (files could have changed)
        rescan_result = run_all_scans(str(proj_dir))
        if rescan_result.status != "passed":
            deployment.status = "failed"
            deployment.logs = sanitize_logs(
                f"Deployment aborted during pre-build re-scan: project is no longer clean.\n"
                f"Status: {rescan_result.status}. Reason: {rescan_result.blocked_reason}\n"
                f"Findings count: {len(rescan_result.findings)}",
                secret_vals,
            )
            deployment.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        # Step 2: If project has Dockerfile, lint it
        dockerfile_path = proj_dir / "Dockerfile"
        if dockerfile_path.exists():
            dockerfile_findings = lint_dockerfile(str(dockerfile_path))
            high_findings = [f for f in dockerfile_findings if f.severity in ("high", "critical")]
            if high_findings:
                deployment.status = "failed"
                reasons = [f"Line {f.line}: {f.type} ({f.severity}) - {f.masked_preview}" for f in high_findings]
                deployment.logs = sanitize_logs(
                    "Deployment blocked by Dockerfile security linter:\n" + "\n".join(reasons),
                    secret_vals,
                )
                deployment.finished_at = datetime.now(timezone.utc)
                db.commit()
                return

        # Step 3: Run Build via Deployer abstraction
        deployer = get_deployer()
        deployment.logs = sanitize_logs("Building Docker image...\n", secret_vals)
        db.commit()

        try:
            build_logs = deployer.build(str(proj_dir), deployment.image_tag)
            deployment.logs = sanitize_logs(deployment.logs + build_logs, secret_vals)
            db.commit()
        except Exception as build_err:
            deployment.status = "failed"
            deployment.logs = sanitize_logs(deployment.logs + f"\nBuild failed: {str(build_err)}", secret_vals)
            deployment.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        # Step 4: Run Container via Deployer with runtime secrets injection
        deployment.status = "deploying"
        db.commit()

        try:
            run_logs = deployer.run(
                deployment.image_tag,
                deployment.container_name,
                deployment.port or 9000,
                env_file_path=env_file_path,
            )
            deployment.logs = sanitize_logs(deployment.logs + "\n" + run_logs, secret_vals)
            db.commit()
        except Exception as run_err:
            deployment.status = "failed"
            deployment.logs = sanitize_logs(deployment.logs + f"\nDeploy failed: {str(run_err)}", secret_vals)
            deployment.finished_at = datetime.now(timezone.utc)
            db.commit()
            return
        finally:
            # Enforce deletion of temp env-file immediately after docker run
            if env_file_path and os.path.exists(env_file_path):
                try:
                    os.remove(env_file_path)
                except Exception:
                    pass
            if env_temp_dir and os.path.exists(env_temp_dir):
                shutil.rmtree(env_temp_dir, ignore_errors=True)

        # Step 5: Post-deployment Exposure Probe
        deployment.status = "probing"
        deployment.logs = sanitize_logs(deployment.logs + "\nRunning post-deployment exposure probe...\n", secret_vals)
        db.commit()

        try:
            verify_tls = os.getenv("PROBE_VERIFY_TLS", "false").strip().lower() in ("true", "1", "yes")
            probe_res = probe_deployment(deployment.url, verify_tls=verify_tls)

            # Persist probe results
            for item in probe_res.items:
                rec = ProbeResultRecord(
                    deployment_id=deployment.id,
                    path=item.path,
                    status_code=item.status,
                    verdict=item.verdict,
                    note=item.note,
                )
                db.add(rec)
            db.commit()

            if probe_res.exposed_count > 0:
                deployment.status = "exposed"
                auto_stop = os.getenv("AUTO_STOP_ON_EXPOSURE", "true").strip().lower() in ("true", "1", "yes")
                if auto_stop:
                    try:
                        deployer.stop(deployment.container_name)
                    except Exception:
                        pass
                    deployment.logs = sanitize_logs(
                        deployment.logs
                        + f"\n[EXPOSURE ALERT] Post-deployment probe detected {probe_res.exposed_count} exposed sensitive item(s). "
                        + "Container automatically stopped to protect environment (AUTO_STOP_ON_EXPOSURE=true).",
                        secret_vals,
                    )
                else:
                    deployment.logs = sanitize_logs(
                        deployment.logs
                        + f"\n[EXPOSURE ALERT] Post-deployment probe detected {probe_res.exposed_count} exposed sensitive item(s). "
                        + "Container remains running (AUTO_STOP_ON_EXPOSURE=false).",
                        secret_vals,
                    )
            else:
                deployment.status = "deployed"
                deployment.logs = sanitize_logs(
                    deployment.logs
                    + f"\n[PROBE PASSED] Security probe completed successfully. Zero exposed paths detected across {len(probe_res.items)} checks.",
                    secret_vals,
                )

        except Exception as probe_err:
            deployment.status = "deployed"
            deployment.logs = sanitize_logs(
                deployment.logs + f"\n[PROBE WARNING] Post-deployment probe skipped or encountered an error: {str(probe_err)}",
                secret_vals,
            )

        deployment.finished_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as exc:
        deployment = db.query(DeploymentRecord).filter(DeploymentRecord.id == deployment_id).first()
        if deployment:
            deployment.status = "failed"
            deployment.logs = sanitize_logs(deployment.logs + f"\nFatal deployment error: {str(exc)}", secret_vals)
            deployment.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        # Enforce temp env-file deletion if still present
        if env_file_path and os.path.exists(env_file_path):
            try:
                os.remove(env_file_path)
            except Exception:
                pass
        if env_temp_dir and os.path.exists(env_temp_dir):
            shutil.rmtree(env_temp_dir, ignore_errors=True)

        db.close()
        # Clean up approved project folder after deploy
        if proj_dir.exists():
            shutil.rmtree(proj_dir, ignore_errors=True)


@router.post("/scans/{scan_id}/deploy", response_model=DeploymentOut, status_code=status.HTTP_201_CREATED)
def trigger_scan_deploy(
    scan_id: int,
    background_tasks: BackgroundTasks,
    payload: DeployRequest | None = None,
    db: Session = Depends(get_db),
) -> dict:
    """Trigger container deployment for an approved scan. Blocked scans return 409. Accepts optional project slug for secrets."""
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan {scan_id} not found")

    if scan.status != "passed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot deploy scan with status '{scan.status}'. Only scans with status 'passed' can be deployed.",
        )

    project_slug = payload.project.strip() if payload and payload.project else None
    if project_slug:
        try:
            validate_project_slug(project_slug)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    configured_ws = Path(os.getenv("WORKSPACE_ROOT", "./workspace")).resolve()
    approved_dir = configured_ws / "approved" / str(scan_id)

    # If approved directory doesn't exist, check if source path exists (e.g. from local scan or sample-repos)
    if not approved_dir.exists():
        src_path = Path(scan.source)
        if not src_path.exists():
            # Check relative to workspace or backend
            alt = Path("tests/sample-repos") / Path(scan.source).name
            if alt.exists():
                src_path = alt
        if src_path.exists() and src_path.is_dir():
            approved_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src_path, approved_dir, dirs_exist_ok=True)
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Approved source code for scan {scan_id} has expired or is unavailable.",
            )

    short_id = str(uuid.uuid4())[:8]
    sanitized_scan_id = sanitize_identifier(f"scan-{scan_id}")
    image_tag = f"securedeploy/{sanitized_scan_id}:{short_id}"
    container_name = f"securedeploy-{sanitized_scan_id}-{short_id}"

    port = allocate_next_port(db)
    host_target = os.getenv("DEPLOY_TARGET", "local").strip().lower()
    url = f"http://127.0.0.1:{port}" if host_target == "local" else f"https://{os.getenv('EC2_HOST', 'localhost')}/{container_name}/"

    deployment = DeploymentRecord(
        scan_id=scan.id,
        project=project_slug,
        status="pending",
        image_tag=image_tag,
        container_name=container_name,
        port=port,
        url=url,
        host_type=host_target,
        logs="Deployment queued...\n",
    )
    db.add(deployment)
    db.commit()
    db.refresh(deployment)

    background_tasks.add_task(execute_deployment_task, deployment.id, str(approved_dir), project_slug)

    return {
        "id": deployment.id,
        "scan_id": deployment.scan_id,
        "project": deployment.project,
        "status": deployment.status,
        "image_tag": deployment.image_tag,
        "container_name": deployment.container_name,
        "port": deployment.port,
        "url": deployment.url,
        "host_type": deployment.host_type,
        "logs": deployment.logs,
        "created_at": deployment.created_at,
        "finished_at": deployment.finished_at,
    }


@router.get("/deployments", response_model=list[DeploymentOut])
def list_deployments(db: Session = Depends(get_db)) -> list[dict]:
    """List all deployments from newest to oldest."""
    deployments = db.query(DeploymentRecord).order_by(DeploymentRecord.id.desc()).all()
    return [
        {
            "id": d.id,
            "scan_id": d.scan_id,
            "project": d.project,
            "status": d.status,
            "image_tag": d.image_tag,
            "container_name": d.container_name,
            "port": d.port,
            "url": d.url,
            "host_type": d.host_type,
            "logs": d.logs,
            "created_at": d.created_at,
            "finished_at": d.finished_at,
        }
        for d in deployments
    ]


@router.get("/deployments/{deployment_id}", response_model=DeploymentOut)
def get_deployment(deployment_id: int, db: Session = Depends(get_db)) -> dict:
    """Retrieve deployment details including logs."""
    deployment = db.query(DeploymentRecord).filter(DeploymentRecord.id == deployment_id).first()
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {deployment_id} not found",
        )
    return {
        "id": deployment.id,
        "scan_id": deployment.scan_id,
        "project": deployment.project,
        "status": deployment.status,
        "image_tag": deployment.image_tag,
        "container_name": deployment.container_name,
        "port": deployment.port,
        "url": deployment.url,
        "host_type": deployment.host_type,
        "logs": deployment.logs,
        "created_at": deployment.created_at,
        "finished_at": deployment.finished_at,
    }


@router.post("/deployments/{deployment_id}/stop", response_model=DeploymentOut)
def stop_deployment(deployment_id: int, db: Session = Depends(get_db)) -> dict:
    """Stop and terminate an active container deployment."""
    deployment = db.query(DeploymentRecord).filter(DeploymentRecord.id == deployment_id).first()
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {deployment_id} not found",
        )

    deployer = get_deployer()
    try:
        deployer.stop(deployment.container_name)
    except Exception:
        pass

    deployment.status = "stopped"
    deployment.logs = sanitize_logs(deployment.logs + "\nContainer stopped by user request.")
    deployment.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(deployment)

    return {
        "id": deployment.id,
        "scan_id": deployment.scan_id,
        "project": deployment.project,
        "status": deployment.status,
        "image_tag": deployment.image_tag,
        "container_name": deployment.container_name,
        "port": deployment.port,
        "url": deployment.url,
        "host_type": deployment.host_type,
        "logs": deployment.logs,
        "created_at": deployment.created_at,
        "finished_at": deployment.finished_at,
    }


@router.get("/deployments/{deployment_id}/probe")
def get_deployment_probe(deployment_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve the latest post-deploy security probe findings for a deployment."""
    deployment = db.query(DeploymentRecord).filter(DeploymentRecord.id == deployment_id).first()
    if not deployment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Deployment {deployment_id} not found")

    records = (
        db.query(ProbeResultRecord)
        .filter(ProbeResultRecord.deployment_id == deployment_id)
        .order_by(ProbeResultRecord.id.asc())
        .all()
    )

    exposed_count = sum(1 for r in records if r.verdict == "exposed")
    warning_count = sum(1 for r in records if r.verdict == "warning")
    overall = "exposed" if exposed_count > 0 else ("warning" if warning_count > 0 else "safe")

    return {
        "deployment_id": deployment_id,
        "overall_verdict": overall,
        "exposed_count": exposed_count,
        "warning_count": warning_count,
        "items": [
            {
                "path": r.path,
                "status": r.status_code,
                "verdict": r.verdict,
                "note": r.note,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ],
    }


@router.post("/deployments/{deployment_id}/probe")
def rerun_deployment_probe(deployment_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Re-run the post-deploy security probe on demand against the deployment's target URL."""
    deployment = db.query(DeploymentRecord).filter(DeploymentRecord.id == deployment_id).first()
    if not deployment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Deployment {deployment_id} not found")

    if not deployment.url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Deployment does not have an active URL")

    verify_tls = os.getenv("PROBE_VERIFY_TLS", "false").strip().lower() in ("true", "1", "yes")
    try:
        result = probe_deployment(deployment.url, verify_tls=verify_tls)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # Replace previous probe records
    db.query(ProbeResultRecord).filter(ProbeResultRecord.deployment_id == deployment_id).delete()
    for item in result.items:
        rec = ProbeResultRecord(
            deployment_id=deployment.id,
            path=item.path,
            status_code=item.status,
            verdict=item.verdict,
            note=item.note,
        )
        db.add(rec)

    if result.exposed_count > 0:
        deployment.status = "exposed"
        auto_stop = os.getenv("AUTO_STOP_ON_EXPOSURE", "true").strip().lower() in ("true", "1", "yes")
        if auto_stop:
            deployer = get_deployer()
            try:
                deployer.stop(deployment.container_name)
            except Exception:
                pass
            deployment.logs = sanitize_logs(
                deployment.logs + f"\n[SECURITY PROBE] Re-run detected {result.exposed_count} exposed path(s). Container stopped."
            )
    else:
        if deployment.status == "exposed":
            deployment.status = "deployed"

    db.commit()
    db.refresh(deployment)

    return {
        "deployment_id": deployment_id,
        "status": deployment.status,
        "overall_verdict": result.overall_verdict,
        "exposed_count": result.exposed_count,
        "warning_count": result.warning_count,
        "items": [asdict(item) for item in result.items],
    }
