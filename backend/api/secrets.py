from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from api.scans import enforce_rate_limit
from db import SecretMetadataRecord, get_db
from secrets_store import (
    SecretValidationError,
    get_secrets_store,
    validate_project_slug,
    validate_secret_name,
    validate_secret_value,
)

router = APIRouter(prefix="/api/projects", tags=["secrets"])

MASKED_SECRET_CONSTANT = "••••••••"


@router.put("/{project}/secrets/{name}", status_code=status.HTTP_200_OK)
async def put_secret(
    project: str,
    name: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Store an encrypted secret for a project (write-only).
    
    The secret value is never logged, never returned in API responses, and never stored in the database.
    """
    enforce_rate_limit(request)

    # Validate slugs and names first
    try:
        validate_project_slug(project)
        validate_secret_name(name)
    except SecretValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # Read and parse body without logging or echoing the payload
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON body: request body must be a valid JSON object",
        )

    if not isinstance(body, dict) or "value" not in body:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Missing required field 'value'",
        )

    val = body["value"]
    if not isinstance(val, str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Secret value must be a string",
        )

    try:
        validate_secret_value(val)
        store = get_secrets_store()
        store.put(project, name, val)
    except SecretValidationError as exc:
        # Crucial: validation messages are generic and never echo back the secret value
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error while securely storing secret",
        )

    backend_name = os.getenv("SECRETS_BACKEND", "local").strip().lower()
    now = datetime.now(timezone.utc)
    rec = (
        db.query(SecretMetadataRecord)
        .filter(
            SecretMetadataRecord.project == project,
            SecretMetadataRecord.name == name,
        )
        .first()
    )
    if rec:
        rec.updated_at = now
        rec.backend = backend_name
    else:
        rec = SecretMetadataRecord(
            project=project,
            name=name,
            backend=backend_name,
            created_at=now,
            updated_at=now,
        )
        db.add(rec)
    db.commit()

    return {
        "project": project,
        "name": name,
        "status": "stored",
    }


@router.get("/{project}/secrets")
def list_project_secrets(
    project: str,
    request: Request,
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """List secret metadata for a project. Secret values are NEVER returned."""
    enforce_rate_limit(request)
    try:
        validate_project_slug(project)
    except SecretValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    records = (
        db.query(SecretMetadataRecord)
        .filter(SecretMetadataRecord.project == project)
        .order_by(SecretMetadataRecord.name.asc())
        .all()
    )

    return [
        {
            "name": r.name,
            "masked": MASKED_SECRET_CONSTANT,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in records
    ]


@router.delete("/{project}/secrets/{name}")
def delete_secret(
    project: str,
    name: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Delete a secret for a project."""
    enforce_rate_limit(request)
    try:
        validate_project_slug(project)
        validate_secret_name(name)
    except SecretValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    store = get_secrets_store()
    deleted_from_store = store.delete(project, name)

    rec = (
        db.query(SecretMetadataRecord)
        .filter(
            SecretMetadataRecord.project == project,
            SecretMetadataRecord.name == name,
        )
        .first()
    )
    if rec:
        db.delete(rec)
        db.commit()

    if not deleted_from_store and not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret '{name}' not found for project '{project}'",
        )

    return {
        "project": project,
        "name": name,
        "status": "deleted",
    }
