# scripts/db_init_prod.py
import asyncio
import logging
import os
from app.db import init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("db_init_prod")

async def main():
    logger.info("Initializing production database schema...")
    try:
        await init_db()
        logger.info("Database schema initialized and verified successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise e
        
    if os.getenv("SEED_TEST_DATA", "").lower() == "true":
        logger.info("SEED_TEST_DATA environment variable is set to true. Seeding database...")
        from scripts.seed_test_data import seed_data
        try:
             await seed_data()
             logger.info("Seed data loaded successfully.")
        except Exception as e:
             logger.error(f"Failed to seed database: {e}")
             raise e

if __name__ == "__main__":
    asyncio.run(main())
