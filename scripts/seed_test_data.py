import asyncio
import logging
import sys
from app.db import SessionLocal
from app.models import Agent, SessionContext
from app.config import settings

# Setup standard logging to stdout
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("seed_test_data")

async def seed_data():
    logger.info(f"Connecting to database: {settings.DATABASE_URL}")
    
    async with SessionLocal() as db:
        try:
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

            # Commit the transaction
            await db.commit()
            logger.info("Database transaction committed successfully.")
            print("\nSuccess: Test data seeded/updated successfully!")
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error seeding database: {e}", exc_info=True)
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(seed_data())
