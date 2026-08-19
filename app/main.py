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

app = FastAPI(
    title="Agent WAF",
    description="Agent WAF - Policy-enforcing proxy between autonomous agent and tools",
    lifespan=lifespan
)

@app.get("/")
async def read_root():
    return {
        "service": "Agent WAF",
        "status": "running"
    }

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
