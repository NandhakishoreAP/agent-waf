import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.db import Base
from app.models import Agent, ToolCallLog, DispositionEnum

# Use an in-memory SQLite database for testing relationships and operations
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    async_session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    async with async_session() as session:
        yield session
        
    await engine.dispose()

@pytest.mark.asyncio
async def test_db_relations(db_session: AsyncSession):
    # Create an Agent
    agent = Agent(
        agent_id="support-agent-01",
        name="Support Agent",
        declared_scope=["crm.read", "email.send"]
    )
    db_session.add(agent)
    await db_session.commit()
    
    # Create a Tool Call Log
    log = ToolCallLog(
        agent_id="support-agent-01",
        session_id="session-abc123",
        tool_name="crm.read",
        parameters_sanitized={"customer_id": 42},
        rule_evaluations=[],
        final_disposition=DispositionEnum.ALLOWED,
        latency_ms=15
    )
    db_session.add(log)
    await db_session.commit()
    
    # Fetch agent and count logs with selectinload
    stmt = select(Agent).where(Agent.agent_id == "support-agent-01").options(selectinload(Agent.logs))
    result = await db_session.execute(stmt)
    retrieved_agent = result.scalar_one_or_none()
    
    assert retrieved_agent is not None
    assert retrieved_agent.name == "Support Agent"
    assert len(retrieved_agent.logs) == 1
    assert retrieved_agent.logs[0].tool_name == "crm.read"
    assert retrieved_agent.logs[0].final_disposition == DispositionEnum.ALLOWED

def test_health_check_endpoint():
    # Test the API /health endpoint with TestClient (ensuring lifespan initialization occurs)
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["checks"]["database"] == "ok"
        assert data["checks"]["policy"] == "ok"
