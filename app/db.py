from typing import AsyncGenerator
from sqlalchemy import event
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from app.config import settings

import os
from app.config import settings

# SQLite connection args to allow multi-threaded access in development
engine_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    engine_args["connect_args"] = {"check_same_thread": False}
else:
    # PostgreSQL production pooling settings
    engine_args["pool_size"] = int(os.getenv("DATABASE_POOL_SIZE", "10"))
    engine_args["max_overflow"] = int(os.getenv("DATABASE_MAX_OVERFLOW", "20"))
    engine_args["pool_timeout"] = float(os.getenv("DATABASE_POOL_TIMEOUT", "30.0"))
    engine_args["pool_recycle"] = int(os.getenv("DATABASE_POOL_RECYCLE", "1800"))
    engine_args["pool_pre_ping"] = True  # Connection liveness check

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    **engine_args
)

SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()

from sqlalchemy.types import TypeDecorator, DateTime
from datetime import datetime, timezone

class TZDateTime(TypeDecorator):
    """
    SQLAlchemy DataType to ensure timezone-aware UTC datetime objects are used everywhere,
    mapping to TIMESTAMP WITH TIME ZONE in PostgreSQL and timezone-aware datetimes in SQLite.
    """
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        return value

# Configure SQLite to use WAL mode for concurrency safety during local development
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine.sync_engine, "connect")
    def set_wal_mode(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.close()

async def init_db() -> None:
    """Initialize DB tables."""
    # Import models here to register them with Base.metadata and prevent circular imports
    from app.models import Agent, ToolCallLog, RateLimitEvent, SequenceEvent, SessionContext
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency helper to get active database session."""
    async with SessionLocal() as session:
        yield session
