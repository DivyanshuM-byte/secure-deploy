from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from api.deployments import router as deployments_router
from api.scans import StatsOut, calculate_platform_stats, router as scans_router
from api.secrets import router as secrets_router
from db import get_db, init_db


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize SQLite tables on application startup."""
    init_db()
    yield


app = FastAPI(
    title="secure-deploy API",
    description="DevSecOps pre-deployment secret, PII, sensitive file scanner, and automated Docker deploy pipeline.",
    version="0.5.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)
app.include_router(deployments_router)
app.include_router(secrets_router)


@app.get("/api/stats", response_model=StatsOut, tags=["stats"])
def get_stats(db: Session = Depends(get_db)) -> dict:
    """Return platform-wide DevSecOps scanning statistics."""
    return calculate_platform_stats(db)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return service health status."""
    return {"status": "ok"}
