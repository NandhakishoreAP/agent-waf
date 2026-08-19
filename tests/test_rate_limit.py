import asyncio
import os
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy import event, select, func, delete
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.db import Base
from app.models import Agent, RateLimitEvent
from app.rules.rate_limit import RateLimitRule
from app.rules.engine import ToolInvocationContext, RuleEngine, FinalDisposition, RuleEvaluation
from app.schemas import WAFPolicy, RateLimitPolicy

# To support concurrency (asyncio.gather) in SQLite testing, we use a local SQLite file in WAL mode
TEST_DB_FILE = "./test_rate_limit.db"
TEST_DB_URL = f"sqlite+aiosqlite:///{TEST_DB_FILE}"

@pytest_asyncio.fixture
async def db_session():
    # Start fresh by deleting the sqlite database file if it exists from a previous aborted test run
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
            for suffix in ["-wal", "-shm"]:
                if os.path.exists(TEST_DB_FILE + suffix):
                    os.remove(TEST_DB_FILE + suffix)
        except Exception:
            pass
            
    engine = create_async_engine(
        TEST_DB_URL, 
        connect_args={
            "check_same_thread": False, 
            "timeout": 30.0
        }
    )
    
    # Configure WAL mode for the test SQLite database connections
    @event.listens_for(engine.sync_engine, "connect")
    def set_wal_mode(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.close()
        
    async_session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    async with async_session() as session:
        # Clear existing rows to ensure complete isolation
        await session.execute(delete(RateLimitEvent))
        await session.execute(delete(Agent))
        
        # Seed agents so row serialization checks are satisfied
        agent_a = Agent(agent_id="agent-A", name="Agent A", declared_scope=[])
        agent_b = Agent(agent_id="agent-B", name="Agent B", declared_scope=[])
        session.add_all([agent_a, agent_b])
        await session.commit()
        
    yield async_session
    
    await engine.dispose()
    
    # Teardown: delete the test SQLite file and itsWAL log artifacts
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
            for suffix in ["-wal", "-shm"]:
                if os.path.exists(TEST_DB_FILE + suffix):
                    os.remove(TEST_DB_FILE + suffix)
        except Exception:
            pass

def get_waf_policy(mode="enforce", rate_limits=None) -> WAFPolicy:
    if rate_limits is None:
        rate_limits = [
            RateLimitPolicy(tool="crm.read", max_calls=5, window_seconds=60),
            RateLimitPolicy(tool="db.delete", max_calls=2, window_seconds=60)
        ]
    return WAFPolicy(
        policy_version="v1",
        mode=mode,
        rate_limits=rate_limits,
        parameter_validation=[],
        data_scope=[],
        sequence_rules=[]
    )

@pytest.mark.asyncio
async def test_no_policy_for_tool(db_session):
    # 1. No policy configured for tool -> ALLOWED
    async with db_session() as session:
        rule = RateLimitRule()
        policy = get_waf_policy(rate_limits=[])
        context = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="crm.read",
            parameters={},
            session_context={}
        )
        result = await rule.evaluate(context, policy, session)
        assert result.passed is True
        assert "No rate limit configured" in result.reason

@pytest.mark.asyncio
async def test_first_call_allowed(db_session):
    # 2. First crm.read call -> ALLOWED
    async with db_session() as session:
        rule = RateLimitRule()
        policy = get_waf_policy()
        context = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="crm.read",
            parameters={},
            session_context={}
        )
        result = await rule.evaluate(context, policy, session)
        assert result.passed is True
        assert result.reason == "Rate limit not exceeded"

@pytest.mark.asyncio
async def test_limit_reached_and_blocked(db_session):
    # 3. Five crm.read calls -> all ALLOWED
    # 4. Sixth crm.read call within 60 seconds -> BLOCKED
    rule = RateLimitRule()
    policy = get_waf_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    # 5 allowed calls
    for _ in range(5):
        async with db_session() as session:
            res = await rule.evaluate(context, policy, session)
            assert res.passed is True
            assert res.reason == "Rate limit not exceeded"
            
    # 6th call is blocked
    async with db_session() as session:
        res = await rule.evaluate(context, policy, session)
        assert res.passed is False
        assert res.reason == "Rate limit exceeded: 5 calls in 60 seconds"

@pytest.mark.asyncio
async def test_db_delete_limit(db_session):
    # 5. db.delete: first -> ALLOWED, second -> ALLOWED, third -> BLOCKED
    rule = RateLimitRule()
    policy = get_waf_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="db.delete",
        parameters={},
        session_context={}
    )
    
    # First call
    async with db_session() as s:
        assert (await rule.evaluate(context, policy, s)).passed is True
    # Second call
    async with db_session() as s:
        assert (await rule.evaluate(context, policy, s)).passed is True
    # Third call
    async with db_session() as s:
        res = await rule.evaluate(context, policy, s)
        assert res.passed is False
        assert res.reason == "Rate limit exceeded: 2 calls in 60 seconds"

@pytest.mark.asyncio
async def test_independent_agent_limits(db_session):
    # 6. Different agents have independent limits (agent-A and agent-B do not share quota)
    rule = RateLimitRule()
    policy = get_waf_policy()
    
    # Agent A makes 5 calls
    context_a = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    for _ in range(5):
        async with db_session() as s:
            assert (await rule.evaluate(context_a, policy, s)).passed is True
            
    # Agent A's 6th is blocked
    async with db_session() as s:
        assert (await rule.evaluate(context_a, policy, s)).passed is False
        
    # Agent B makes 5 calls (should be allowed completely independently)
    context_b = ToolInvocationContext(
        agent_id="agent-B",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    for _ in range(5):
        async with db_session() as s:
            assert (await rule.evaluate(context_b, policy, s)).passed is True

@pytest.mark.asyncio
async def test_independent_tool_limits(db_session):
    # 7. Different tools have independent limits.
    rule = RateLimitRule()
    policy = get_waf_policy()
    
    context_crm = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    context_del = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="db.delete",
        parameters={},
        session_context={}
    )
    # Fill crm.read limit (5 calls)
    for _ in range(5):
        async with db_session() as s:
            assert (await rule.evaluate(context_crm, policy, s)).passed is True
    # Fill db.delete limit (2 calls)
    for _ in range(2):
        async with db_session() as s:
            assert (await rule.evaluate(context_del, policy, s)).passed is True

@pytest.mark.asyncio
async def test_rolling_window_expiration(db_session):
    # 8. A call outside the rolling window does not count.
    # 9. Expired events are cleaned/ignored correctly.
    rule = RateLimitRule()
    policy = get_waf_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    # Fill 5 calls in the past (e.g. 70 seconds ago)
    past_time = datetime.now(timezone.utc) - timedelta(seconds=70)
    async with db_session() as session:
        for _ in range(5):
            evt = RateLimitEvent(
                agent_id="agent-A",
                tool_name="crm.read",
                timestamp=past_time
            )
            session.add(evt)
        await session.commit()
        
    # Since they are outside the 60 second window, a new call must be ALLOWED
    async with db_session() as session:
        res = await rule.evaluate(context, policy, session)
        assert res.passed is True
        
    # Verify that the 5 older events were successfully deleted from database
    async with db_session() as session:
        stmt = select(func.count(RateLimitEvent.id)).where(RateLimitEvent.agent_id == "agent-A")
        result = await session.execute(stmt)
        assert result.scalar() == 1

@pytest.mark.asyncio
async def test_dynamic_policy_changes(db_session):
    # 10. Policy values are actually read from WAFPolicy.
    # 11. Changing the policy in a test changes the effective rate limit.
    rule = RateLimitRule()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    # Custom policy limiting to max_calls=3
    policy_3 = get_waf_policy(rate_limits=[
        RateLimitPolicy(tool="crm.read", max_calls=3, window_seconds=30)
    ])
    
    # 3 calls allowed
    for _ in range(3):
        async with db_session() as s:
            assert (await rule.evaluate(context, policy_3, s)).passed is True
            
    # 4th call is blocked under the new policy
    async with db_session() as s:
        res = await rule.evaluate(context, policy_3, s)
        assert res.passed is False
        assert res.reason == "Rate limit exceeded: 3 calls in 30 seconds"

@pytest.mark.asyncio
async def test_concurrency_safe_rate_limit(db_session):
    # 12. Concurrent requests cannot bypass the limit.
    rule = RateLimitRule()
    policy = get_waf_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    # Check what is currently in SQLite before starting the concurrent runs
    async with db_session() as s:
        existing_count = await s.scalar(select(func.count(RateLimitEvent.id)))
        print(f"\n[DEBUG] Events in database before concurrency launch: {existing_count}")
        
    async def run_eval():
        async with db_session() as s:
            return await rule.evaluate(context, policy, s)
            
    # Dispatch concurrently
    tasks = [run_eval() for _ in range(10)]
    results = await asyncio.gather(*tasks)
    
    print("\nCONCURRENCY TEST DETAILED RESULTS:")
    for idx, r in enumerate(results):
        print(f"Task {idx}: passed={r.passed}, reason={r.reason}")
        
    passed_count = sum(1 for r in results if r.passed)
    blocked_count = sum(1 for r in results if not r.passed)
    
    assert passed_count == 5
    assert blocked_count == 5

@pytest.mark.asyncio
async def test_db_failure_closes(db_session):
    # 13. Database failure causes fail-closed behavior
    # 14. RuleEvaluation contains useful reasons (e.g. system error)
    rule = RateLimitRule()
    policy = get_waf_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    # Mock a broken block session raising database exceptions
    class BrokenSession:
        @property
        def bind(self):
            class MockEngine:
                class MockDialect:
                    name = "postgresql"
                dialect = MockDialect()
            return MockEngine()
            
        def in_transaction(self):
            return False
            
        def begin(self):
            raise RuntimeError("Database disk or network I/O error")
            
    res = await rule.evaluate(context, policy, BrokenSession())
    assert res.passed is False
    assert "system error" in res.reason

@pytest.mark.asyncio
async def test_rule_engine_integration_and_shadow_mode(db_session):
    # 15. RuleEngine converts a rate-limit failure into BLOCKED in enforce mode.
    # 16. Shadow-mode violation returns SHADOW_BLOCKED without representing it as an actual ALLOWED security result in the evaluation itself.
    
    policy_enforce = get_waf_policy(mode="enforce")
    engine = RuleEngine(policy=policy_enforce, rules=[RateLimitRule()])
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-1",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    
    # Trigger 5 ALLOWED calls
    for _ in range(5):
        async with db_session() as s:
            res = await engine.evaluate(context, s)
            assert res.final_disposition == FinalDisposition.ALLOWED
            
    # 6th call is BLOCKED
    async with db_session() as s:
        res = await engine.evaluate(context, s)
        assert res.final_disposition == FinalDisposition.BLOCKED
        
    # Clear events to verify shadow mode cleanly
    async with db_session() as s:
        await s.execute(delete(RateLimitEvent))
        await s.commit()
        
    # Shadow Mode testing
    policy_shadow = get_waf_policy(mode="shadow")
    engine_shadow = RuleEngine(policy=policy_shadow, rules=[RateLimitRule()])
    
    # Trigger 5 ALLOWED calls first
    for _ in range(5):
        async with db_session() as s:
            res = await engine_shadow.evaluate(context, s)
            assert res.final_disposition == FinalDisposition.ALLOWED
            
    # 6th is SHADOW_BLOCKED
    async with db_session() as s:
        res = await engine_shadow.evaluate(context, s)
        assert res.final_disposition == FinalDisposition.SHADOW_BLOCKED
        # Note: the individual rule evaluation checks still fail (passed is False), but final disposition is mapped.
        assert res.evaluations[0].passed is False
