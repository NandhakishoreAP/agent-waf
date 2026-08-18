from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db import init_db
from app.deps import get_db_session

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    await init_db()
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
async def health_check(db: AsyncSession = Depends(get_db_session)):
    try:
        # Verify db connectivity by executing a simple SELECT 1 query
        await db.execute(text("SELECT 1"))
        return {
            "status": "ok",
            "checks": {
                "database": "ok"
            }
        }
    except Exception:
        # Return HTTP 503 without leaking internal exception details
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection failed"
        )
