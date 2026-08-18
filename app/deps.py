from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import SessionLocal
from app.config import settings, Settings

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI Dependency for database session."""
    async with SessionLocal() as session:
        yield session

def get_settings() -> Settings:
    """FastAPI Dependency for configuration settings."""
    return settings
