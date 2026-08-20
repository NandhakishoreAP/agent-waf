from contextlib import asynccontextmanager
import logging
import contextvars
import os
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

# Set up correlation ID tracking in logs
correlation_id_context = contextvars.ContextVar("correlation_id", default="-")

class CorrelationIdFilter(logging.Filter):
    def filter(self, record):
        record.correlation_id = correlation_id_context.get()
        return True

# Read log level from settings/env
log_level_str = os.getenv("LOG_LEVEL", settings.LOG_LEVEL).upper()
numeric_level = getattr(logging, log_level_str, logging.INFO)

# Configure Root Logger to output structured/formatted logs directly to stdout/stderr
root_logger = logging.getLogger()
root_logger.setLevel(numeric_level)

handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [service=agent-waf] [correlation_id=%(correlation_id)s] [%(name)s] %(message)s')
handler.setFormatter(formatter)
handler.addFilter(CorrelationIdFilter())

root_logger.handlers = [handler]

logger = logging.getLogger("agent_waf.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables for non-production environments
    if settings.APP_ENV.lower() != "production":
        logger.info(f"Initializing database schema in {settings.APP_ENV} mode...")
        await init_db()
    else:
        logger.info("Production mode detected. Bypassing automatic database schema initialization.")
    
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
    
    # Startup/Shutdown cleanup hook
    logger.info("Executing lifespan shutdown cleanups...")
    
    # dispose database connection pool
    try:
        from app.db import engine
        await engine.dispose()
        logger.info("Database engine connections closed successfully.")
    except Exception as e:
        logger.error(f"Error disposing database connections: {e}")
        
    # clear active SSE subscribers
    try:
        from app.observability.publisher import _subscribers
        logger.info(f"Clearing {len(_subscribers)} active SSE subscriber queues.")
        _subscribers.clear()
    except Exception as e:
        logger.error(f"Error cleaning SSE subscribers: {e}")

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
    
    correlation_id_context.set(corr_id)
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

@app.get("/ready")
async def ready_check(request: Request, db: AsyncSession = Depends(get_db_session)):
    """Readiness probe checking database connectivity and policy availability."""
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Readiness Database Failure: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connectivity unreachable"
        )
        
    if not getattr(request.app.state, "policy_loaded", False) or request.app.state.policy is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security policy is not loaded"
        )
        
    return {"status": "ready"}

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
