import pytest
import pytest_asyncio
import os
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.db import Base
from app.models import Agent, SessionContext, ToolCallLog, DispositionEnum
from scripts.seed_test_data import seed_data

TEST_SEED_DB_FILE = "./test_seed_fixture.db"
TEST_SEED_DB_URL = f"sqlite+aiosqlite:///{TEST_SEED_DB_FILE}"

@pytest_asyncio.fixture
async def seed_db_session():
    if os.path.exists(TEST_SEED_DB_FILE):
        try:
            os.remove(TEST_SEED_DB_FILE)
            for suffix in ["-wal", "-shm"]:
                if os.path.exists(TEST_SEED_DB_FILE + suffix):
                    os.remove(TEST_SEED_DB_FILE + suffix)
        except Exception:
            pass
            
    engine = create_async_engine(
        TEST_SEED_DB_URL, 
        connect_args={
            "check_same_thread": False, 
            "timeout": 30.0
        }
    )
    
    async_session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    async with async_session() as session:
        # Clear existing rows to ensure complete isolation
        await session.execute(delete(ToolCallLog))
        await session.execute(delete(SessionContext))
        await session.execute(delete(Agent))
        await session.commit()
        
    yield async_session
    
    await engine.dispose()
    if os.path.exists(TEST_SEED_DB_FILE):
        try:
            os.remove(TEST_SEED_DB_FILE)
            for suffix in ["-wal", "-shm"]:
                if os.path.exists(TEST_SEED_DB_FILE + suffix):
                    os.remove(TEST_SEED_DB_FILE + suffix)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_database_seeding_and_idempotency(seed_db_session):
    # 1. Run seed first time
    async with seed_db_session() as db:
        await seed_data(db=db)

    # 2. Verify agent and session context were inserted
    async with seed_db_session() as db:
        # Verify test-agent-01 exists
        res = await db.execute(select(Agent).where(Agent.agent_id == "test-agent-01"))
        agent = res.scalar_one_or_none()
        assert agent is not None
        assert agent.name == "Test Agent"

        # Verify test-session-01 exists and has customer_id = CUST-1001
        res = await db.execute(select(SessionContext).where(SessionContext.session_id == "test-session-01"))
        session_ctx = res.scalar_one_or_none()
        assert session_ctx is not None
        assert session_ctx.customer_id == "CUST-1001"

        # Verify test-session-seq-fail exists and has customer_id = CUST-1001
        res = await db.execute(select(SessionContext).where(SessionContext.session_id == "test-session-seq-fail"))
        session_ctx_seq = res.scalar_one_or_none()
        assert session_ctx_seq is not None
        assert session_ctx_seq.customer_id == "CUST-1001"

    # 3. Seed again to verify idempotency
    async with seed_db_session() as db:
        await seed_data(db=db)

    # Verify no duplicates are created and data remains correct
    async with seed_db_session() as db:
        res = await db.execute(select(Agent))
        agents = res.scalars().all()
        assert len(agents) == 1
        assert agents[0].agent_id == "test-agent-01"

        res = await db.execute(select(SessionContext))
        sessions = res.scalars().all()
        assert len(sessions) == 2
        session_ids = {s.session_id for s in sessions}
        assert "test-session-01" in session_ids
        assert "test-session-seq-fail" in session_ids

    # 4. Verify audit log creation referencing test-agent-01 works without Foreign Key failures
    async with seed_db_session() as db:
        audit_log = ToolCallLog(
            id="test-log-fk-ok",
            agent_id="test-agent-01",
            session_id="test-session-01",
            tool_name="crm.read",
            parameters_sanitized={"customer_id": "CUST-1001"},
            rule_evaluations=[],
            final_disposition=DispositionEnum.ALLOWED,
            latency_ms=12,
            correlation_id="corr-seed-test"
        )
        db.add(audit_log)
        await db.commit()

        # Query back and verify
        res = await db.execute(select(ToolCallLog).where(ToolCallLog.id == "test-log-fk-ok"))
        log = res.scalar_one_or_none()
        assert log is not None
        assert log.agent_id == "test-agent-01"


@pytest.mark.asyncio
async def test_postgresql_seeding_and_idempotency():
    pg_url = "postgresql+asyncpg://waf_user:devpassword@localhost:54321/agent_waf"
    engine = create_async_engine(pg_url)
    async_session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    
    try:
        # Check connection
        async with engine.connect() as conn:
            pass
    except Exception as e:
        pytest.skip(f"PostgreSQL is not available: {e}")
        
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    async with async_session() as session:
        # Clear existing rows to ensure complete isolation
        await session.execute(delete(ToolCallLog))
        await session.execute(delete(SessionContext))
        await session.execute(delete(Agent))
        await session.commit()
        
    try:
        # 1. Run seed first time
        async with async_session() as db:
            await seed_data(db=db)

        # 2. Verify agent and session context were inserted
        async with async_session() as db:
            res = await db.execute(select(Agent).where(Agent.agent_id == "test-agent-01"))
            agent = res.scalar_one_or_none()
            assert agent is not None
            assert agent.name == "Test Agent"

            res = await db.execute(select(SessionContext).where(SessionContext.session_id == "test-session-01"))
            session_ctx = res.scalar_one_or_none()
            assert session_ctx is not None
            assert session_ctx.customer_id == "CUST-1001"

            res = await db.execute(select(SessionContext).where(SessionContext.session_id == "test-session-seq-fail"))
            session_ctx_seq = res.scalar_one_or_none()
            assert session_ctx_seq is not None
            assert session_ctx_seq.customer_id == "CUST-1001"

        # 3. Seed again to verify idempotency
        async with async_session() as db:
            await seed_data(db=db)

        # Verify no duplicates are created and data remains correct
        async with async_session() as db:
            res = await db.execute(select(Agent))
            agents = res.scalars().all()
            assert len(agents) == 1
            assert agents[0].agent_id == "test-agent-01"

            res = await db.execute(select(SessionContext))
            sessions = res.scalars().all()
            assert len(sessions) == 2

        # 4. Verify audit log creation referencing test-agent-01 works without Foreign Key failures
        async with async_session() as db:
            audit_log = ToolCallLog(
                id="test-log-fk-ok-pg",
                agent_id="test-agent-01",
                session_id="test-session-01",
                tool_name="crm.read",
                parameters_sanitized={"customer_id": "CUST-1001"},
                rule_evaluations=[],
                final_disposition=DispositionEnum.ALLOWED,
                latency_ms=12,
                correlation_id="corr-seed-test"
            )
            db.add(audit_log)
            await db.commit()

            # Query back and verify
            res = await db.execute(select(ToolCallLog).where(ToolCallLog.id == "test-log-fk-ok-pg"))
            log = res.scalar_one_or_none()
            assert log is not None
            assert log.agent_id == "test-agent-01"
            
            # Clean up test log
            await db.execute(delete(ToolCallLog).where(ToolCallLog.id == "test-log-fk-ok-pg"))
            await db.commit()
    finally:
        await engine.dispose()
