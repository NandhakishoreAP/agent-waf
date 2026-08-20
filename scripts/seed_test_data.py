import asyncio
import logging
import sys
import os
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import SessionLocal
from app.models import Agent, SessionContext
from app.config import settings

# Setup standard logging to stdout
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("seed_test_data")

async def _run_seed(db: AsyncSession):
    # 1. Create or update the agent
    agent = Agent(
        agent_id="test-agent-01",
        name="Test Agent",
        declared_scope=[]
    )
    # Use merge to ensure idempotency and update existing records
    await db.merge(agent)
    logger.info("Agent 'test-agent-01' merged successfully.")

    # 2. Create or update the SessionContext
    session_context = SessionContext(
        session_id="test-session-01",
        customer_id="CUST-1001"
    )
    # Use merge to ensure idempotency and update existing records
    await db.merge(session_context)
    logger.info("SessionContext 'test-session-01' -> 'CUST-1001' merged successfully.")

    session_context_seq = SessionContext(
        session_id="test-session-seq-fail",
        customer_id="CUST-1001"
    )
    await db.merge(session_context_seq)
    logger.info("SessionContext 'test-session-seq-fail' -> 'CUST-1001' merged successfully.")

    # Commit the transaction
    await db.commit()
    logger.info("Database transaction committed successfully.")

async def seed_data(db: AsyncSession = None):
    # Verify environment matches settings (prevent silent SQLite fallback)
    env_db_url = os.getenv("DATABASE_URL")
    if env_db_url and env_db_url != settings.DATABASE_URL:
         raise ValueError(
             f"Environment DATABASE_URL ('{env_db_url}') differs from Settings value ('{settings.DATABASE_URL}'). "
             "Check configuration to prevent silent fallback to SQLite."
         )

    logger.info(f"Targeting database URL: {settings.DATABASE_URL}")
    
    if db is None:
        async with SessionLocal() as session:
            try:
                await _run_seed(session)
                print("\nSuccess: Test data seeded/updated successfully!")
            except Exception as e:
                await session.rollback()
                logger.error(f"Error seeding database: {e}", exc_info=True)
                sys.exit(1)
    else:
        # Run directly on passed session
        await _run_seed(db)

if __name__ == "__main__":
    asyncio.run(seed_data())
