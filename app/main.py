from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db import init_db
from app.deps import get_db_session
from app.config import settings, load_policy_yaml
from app.schemas import WAFPolicy
from app.api.waf import router as waf_router
from app.api.agent import router as agent_router

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent_waf.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    await init_db()
    
    # Load WAF policy
    try:
        app.state.policy = load_policy_yaml(settings.POLICY_FILE)
        app.state.policy_loaded = True
        logger.info(f"Loaded policy version: {app.state.policy.policy_version}")
    except Exception as e:
        logger.error(f"FATAL: Failed to load security policy: {e}")
        app.state.policy = None
        app.state.policy_loaded = False
        
    yield

import uuid
import re

app = FastAPI(
    title="Agent WAF",
    description="Agent WAF - Policy-enforcing proxy between autonomous agent and tools",
    lifespan=lifespan
)

CORRELATION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")

@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    # Fetch correlation ID from header, generate if missing/invalid
    corr_id = request.headers.get("X-Correlation-ID")
    if not corr_id or not CORRELATION_ID_PATTERN.match(corr_id):
        corr_id = str(uuid.uuid4())
    
    request.state.correlation_id = corr_id
    
    response = await call_next(request)
    # Propagate to client
    response.headers["X-Correlation-ID"] = corr_id
    return response

# Import observability router
from app.api.observability import router as observability_router

from fastapi.responses import HTMLResponse
import os

app.include_router(waf_router)
app.include_router(agent_router)
app.include_router(observability_router)

@app.get("/")
async def read_root():
    return {
        "service": "Agent WAF",
        "status": "running"
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the security WAF observability dashboard template console."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "static", "dashboard.html")
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dashboard static file template not found."
        )

@app.get("/health")
async def health_check(request: Request, db: AsyncSession = Depends(get_db_session)):
    checks = {}
    database_ok = False
    policy_ok = False

    # Check Database Connectivity
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
        database_ok = True
    except Exception as e:
        logger.error(f"Health Check Database Failure: {e}")
        checks["database"] = "error"

    # Check WAF Policy Status
    if getattr(request.app.state, "policy_loaded", False) and request.app.state.policy is not None:
        checks["policy"] = "ok"
        policy_ok = True
    else:
        checks["policy"] = "error"

    # Check Observability status
    checks["observability"] = "ok" if settings.OBSERVABILITY_ENABLED else "disabled"

    # If any check fails, return HTTP 503 Service Unavailable
    if not database_ok or not policy_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "checks": checks
            }
        )

    return {
        "status": "ok",
        "checks": checks
    }

@app.get("/api/policy", response_model=WAFPolicy)
async def get_policy(request: Request):
    """
    Exposes the currently loaded parsed security policy as JSON.
    """
    if not getattr(request.app.state, "policy_loaded", False) or request.app.state.policy is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No active policy loaded"
        )
    return request.app.state.policy

@app.post("/api/policy/reload")
async def reload_policy(request: Request):
    """
    Reloads, parses, and validates the policy file.
    Atomic reload guarantees that the prior policy is retained if the new configuration is invalid.
    """
    try:
        new_policy = load_policy_yaml(settings.POLICY_FILE)
        
        # Atomically replace previous policy
        request.app.state.policy = new_policy
        request.app.state.policy_loaded = True
        logger.info(f"Atomically reloaded policy version: {new_policy.policy_version}")
        
        return {
            "status": "success",
            "policy_version": new_policy.policy_version
        }
    except Exception as e:
        logger.error(f"Policy reload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy validation failed"
        )
