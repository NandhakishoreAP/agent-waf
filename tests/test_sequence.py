import asyncio
import os
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy import event, select, delete
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.db import Base
from app.models import Agent, SequenceEvent
from app.rules.sequence import SequenceRule, SequenceRepository
from app.rules.engine import ToolInvocationContext, RuleEngine, FinalDisposition, RuleEvaluation
from app.schemas import WAFPolicy, SequencePolicy

TEST_DB_FILE = "./test_sequence.db"
TEST_DB_URL = f"sqlite+aiosqlite:///{TEST_DB_FILE}"

@pytest_asyncio.fixture
async def db_session():
    # Start fresh by deleting the sqlite database file if it exists
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
        await session.execute(delete(SequenceEvent))
        await session.execute(delete(Agent))
        
        # Seed agents
        agent_a = Agent(agent_id="agent-A", name="Agent A", declared_scope=[])
        agent_b = Agent(agent_id="agent-B", name="Agent B", declared_scope=[])
        session.add_all([agent_a, agent_b])
        await session.commit()
        
    yield async_session
    
    await engine.dispose()
    
    # Teardown: delete the test SQLite file
    if os.path.exists(TEST_DB_FILE):
        try:
            os.remove(TEST_DB_FILE)
            for suffix in ["-wal", "-shm"]:
                if os.path.exists(TEST_DB_FILE + suffix):
                    os.remove(TEST_DB_FILE + suffix)
        except Exception:
            pass

def get_scope_policy(mode="enforce", sequence_rules=None) -> WAFPolicy:
    if sequence_rules is None:
        sequence_rules = [
            SequencePolicy(tool="email.send", requires_prior=["crm.read"]),
            SequencePolicy(tool="db.delete", requires_prior=["db.backup_check"])
        ]
    return WAFPolicy(
        policy_version="v1",
        mode=mode,
        rate_limits=[],
        parameter_validation=[],
        data_scope=[],
        sequence_rules=sequence_rules
    )

@pytest.mark.asyncio
async def test_email_send_blocked_initially(db_session):
    # 1. New session -> email.send -> BLOCKED
    async with db_session() as s:
        rule = SequenceRule()
        policy = get_scope_policy()
        context = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="email.send",
            parameters={},
            session_context={}
        )
        res = await rule.evaluate(context, policy, s)
        assert res.passed is False
        assert "predecessor tool has not successfully completed" in res.reason

@pytest.mark.asyncio
async def test_email_send_allowed_after_predecessor_success(db_session):
    # 2. crm.read succeeds -> email.send -> ALLOWED
    # Record predecessor crm.read success
    async with db_session() as s:
        context_crm = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="crm.read",
            parameters={},
            session_context={}
        )
        await SequenceRepository.record_successful_tool_call_from_context(s, context_crm)
        
    # Evaluate dependent tool email.send
    async with db_session() as s:
        rule = SequenceRule()
        policy = get_scope_policy()
        context_email = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="email.send",
            parameters={},
            session_context={}
        )
        res = await rule.evaluate(context_email, policy, s)
        assert res.passed is True

@pytest.mark.asyncio
async def test_predecessor_blocked_does_not_satisfy(db_session):
    # 3. crm.read is blocked (meaning it is NEVER recorded as successful) -> email.send -> BLOCKED
    # Evaluate dependent tool email.send: crm.read record doesn't exist
    async with db_session() as s:
        rule = SequenceRule()
        policy = get_scope_policy()
        context_email = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="email.send",
            parameters={},
            session_context={}
        )
        res = await rule.evaluate(context_email, policy, s)
        assert res.passed is False

@pytest.mark.asyncio
async def test_predecessor_success_is_non_adjacent(db_session):
    # 4. crm.read succeeds -> unrelated tool -> email.send -> ALLOWED
    async with db_session() as s:
        # Predecessor
        ctx_crm = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="crm.read",
            parameters={},
            session_context={}
        )
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx_crm)
        # Unrelated
        ctx_unrelated = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="crm.write",
            parameters={},
            session_context={}
        )
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx_unrelated)

    # Dependent tool check
    async with db_session() as s:
        rule = SequenceRule()
        policy = get_scope_policy()
        context_email = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-1",
            tool_name="email.send",
            parameters={},
            session_context={}
        )
        res = await rule.evaluate(context_email, policy, s)
        assert res.passed is True

@pytest.mark.asyncio
async def test_db_delete_states(db_session):
    # 5. New session: db.delete -> BLOCKED
    # 6. db.backup_check succeeds -> db.delete -> ALLOWED
    # 7. db.backup_check blocked -> db.delete -> BLOCKED
    rule = SequenceRule()
    policy = get_scope_policy()

    # Initial Blocked
    async with db_session() as s:
        ctx_del = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-2",
            tool_name="db.delete",
            parameters={},
            session_context={}
        )
        res = await rule.evaluate(ctx_del, policy, s)
        assert res.passed is False

    # Success records backup_check
    async with db_session() as s:
        ctx_check = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-2",
            tool_name="db.backup_check",
            parameters={},
            session_context={}
        )
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx_check)

    # Allowed after backup check
    async with db_session() as s:
        res = await rule.evaluate(ctx_del, policy, s)
        assert res.passed is True

@pytest.mark.asyncio
async def test_session_isolation(db_session):
    # 8. Session A: crm.read -> Session B: email.send -> BLOCKED
    # 9. Session A: crm.read -> Session A: email.send -> ALLOWED
    rule = SequenceRule()
    policy = get_scope_policy()

    # Write in Session A
    async with db_session() as s:
        ctx_crm_a = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-A",
            tool_name="crm.read",
            parameters={},
            session_context={}
        )
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx_crm_a)

    # Read in Session B -> BLOCKED
    async with db_session() as s:
        ctx_email_b = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-B",
            tool_name="email.send",
            parameters={},
            session_context={}
        )
        res_b = await rule.evaluate(ctx_email_b, policy, s)
        assert res_b.passed is False

    # Read in Session A -> ALLOWED
    async with db_session() as s:
        ctx_email_a = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-A",
            tool_name="email.send",
            parameters={},
            session_context={}
        )
        res_a = await rule.evaluate(ctx_email_a, policy, s)
        assert res_a.passed is True

@pytest.mark.asyncio
async def test_agent_isolation(db_session):
    # 10. Agent A Session A: crm.read -> Agent B Session B: email.send -> BLOCKED
    rule = SequenceRule()
    policy = get_scope_policy()

    async with db_session() as s:
        ctx_a = ToolInvocationContext(
            agent_id="agent-A",
            session_id="session-A",
            tool_name="crm.read",
            parameters={},
            session_context={}
        )
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx_a)

    async with db_session() as s:
        ctx_b = ToolInvocationContext(
            agent_id="agent-B",
            session_id="session-B",
            tool_name="email.send",
            parameters={},
            session_context={}
        )
        res = await rule.evaluate(ctx_b, policy, s)
        assert res.passed is False

@pytest.mark.asyncio
async def test_multiple_required_tools(db_session):
    # 11. tool_c requires tool_a and tool_b.
    # Only tool_a completed -> BLOCKED
    # Only tool_b completed -> BLOCKED
    # Both completed -> ALLOWED
    policy = get_scope_policy(sequence_rules=[
        SequencePolicy(tool="tool_c", requires_prior=["tool_a", "tool_b"])
    ])
    rule = SequenceRule()
    ctx_c = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-multi",
        tool_name="tool_c",
        parameters={},
        session_context={}
    )

    # Initial: BLOCKED
    async with db_session() as s:
        assert (await rule.evaluate(ctx_c, policy, s)).passed is False

    # Record tool_a success only
    async with db_session() as s:
        await SequenceRepository.record_successful_tool_call_from_context(
            s, 
            ToolInvocationContext(agent_id="agent-A", session_id="session-multi", tool_name="tool_a", parameters={}, session_context={})
        )
    async with db_session() as s:
        assert (await rule.evaluate(ctx_c, policy, s)).passed is False

    # Record tool_b success
    async with db_session() as s:
        await SequenceRepository.record_successful_tool_call_from_context(
            s, 
            ToolInvocationContext(agent_id="agent-A", session_id="session-multi", tool_name="tool_b", parameters={}, session_context={})
        )
    async with db_session() as s:
        assert (await rule.evaluate(ctx_c, policy, s)).passed is True

@pytest.mark.asyncio
async def test_ordering_constraints(db_session):
    # 12. email.send occurs first (BLOCKED). Then crm.read.
    # The first email.send must be BLOCKED. A later email.send is ALLOWED.
    rule = SequenceRule()
    policy = get_scope_policy()
    
    ctx_email = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-order",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    # First email.send check -> BLOCKED
    async with db_session() as s:
        assert (await rule.evaluate(ctx_email, policy, s)).passed is False

    # Record crm.read
    async with db_session() as s:
        await SequenceRepository.record_successful_tool_call_from_context(
            s,
            ToolInvocationContext(agent_id="agent-A", session_id="session-order", tool_name="crm.read", parameters={}, session_context={})
        )

    # Second email.send check -> ALLOWED
    async with db_session() as s:
        assert (await rule.evaluate(ctx_email, policy, s)).passed is True

@pytest.mark.asyncio
async def test_timestamp_ordering_checks(db_session):
    # 13. A required tool event with timestamp after current invocation must not satisfy requirement
    rule = SequenceRule()
    policy = get_scope_policy()
    
    # Pre-record crm.read with future timestamp
    future_time = datetime.now(timezone.utc) + timedelta(minutes=5)
    async with db_session() as s:
        await SequenceRepository.record_successful_tool_call(
            s,
            session_id="session-time",
            agent_id="agent-A",
            tool_name="crm.read",
            timestamp=future_time
        )
        
    ctx_email = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-time",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    # The current evaluation timestamp is before the stored future event's timestamp. Must block!
    async with db_session() as s:
        assert (await rule.evaluate(ctx_email, policy, s)).passed is False

@pytest.mark.asyncio
async def test_duplicate_success_events_allowed(db_session):
    # 14. crm.read succeeds twice -> email.send -> ALLOWED
    rule = SequenceRule()
    policy = get_scope_policy()

    async with db_session() as s:
        ctx_crm = ToolInvocationContext(agent_id="agent-A", session_id="session-dup", tool_name="crm.read", parameters={}, session_context={})
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx_crm)
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx_crm)

    ctx_email = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-dup",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    async with db_session() as s:
        assert (await rule.evaluate(ctx_email, policy, s)).passed is True

@pytest.mark.asyncio
async def test_no_sequence_policy_configured(db_session):
    # 15. Tool with no sequence policy -> ALLOWED
    rule = SequenceRule()
    policy = get_scope_policy()
    ctx = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-none",
        tool_name="unrelated_tool",
        parameters={},
        session_context={}
    )
    async with db_session() as s:
        res = await rule.evaluate(ctx, policy, s)
        assert res.passed is True
        assert "No sequence rule configured" in res.reason

@pytest.mark.asyncio
async def test_database_failure_fails_closed(db_session):
    # 16. Database failure -> BLOCKED
    rule = SequenceRule()
    policy = get_scope_policy()
    ctx = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-fail",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    
    class BrokenSession:
        def in_transaction(self):
            return False
            
        async def execute(self, stmt):
            raise RuntimeError("Database connection lost")
            
    res = await rule.evaluate(ctx, policy, BrokenSession())
    assert res.passed is False
    assert "predecessor tool has not successfully completed" in res.reason

@pytest.mark.asyncio
async def test_missing_session_or_agent_fails_closed(db_session):
    # 17. Missing session_id -> BLOCKED
    # 18. Missing agent_id -> BLOCKED
    rule = SequenceRule()
    policy = get_scope_policy()
    
    # Missing session_id
    ctx_no_sess = ToolInvocationContext(
        agent_id="agent-A",
        session_id="",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    async with db_session() as s:
        assert (await rule.evaluate(ctx_no_sess, policy, s)).passed is False

    # Missing agent_id
    ctx_no_agent = ToolInvocationContext(
        agent_id="",
        session_id="session-1",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    async with db_session() as s:
        assert (await rule.evaluate(ctx_no_agent, policy, s)).passed is False

@pytest.mark.asyncio
async def test_identity_mismatch_fails_closed(db_session):
    # 19. Identity mismatch: stored event belongs to another agent -> BLOCKED
    rule = SequenceRule()
    policy = get_scope_policy()
    
    # Record crm.read under agent-A
    async with db_session() as s:
        await SequenceRepository.record_successful_tool_call(
            s, 
            session_id="session-mismatch", 
            agent_id="agent-A", 
            tool_name="crm.read", 
            timestamp=datetime.now(timezone.utc)
        )

    # agent-B tries to call email.send inside session-mismatch -> BLOCKED due to identity check
    ctx_mismatch = ToolInvocationContext(
        agent_id="agent-B",
        session_id="session-mismatch",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    async with db_session() as s:
        res = await rule.evaluate(ctx_mismatch, policy, s)
        assert res.passed is False

@pytest.mark.asyncio
async def test_current_tool_must_not_satisfy_itself(db_session):
    # 20. email.send requires crm.read. Only email.send event exists -> BLOCKED
    rule = SequenceRule()
    policy = get_scope_policy()
    
    # Store email.send success
    async with db_session() as s:
        await SequenceRepository.record_successful_tool_call(
            s,
            session_id="session-dup",
            agent_id="agent-A",
            tool_name="email.send",
            timestamp=datetime.now(timezone.utc)
        )
        
    ctx_check = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-dup",
        tool_name="email.send",
        parameters={},
        session_context={}
    )
    # Required predecessor was crm.read, email.send itself doesn't satisfy!
    async with db_session() as s:
        assert (await rule.evaluate(ctx_check, policy, s)).passed is False

@pytest.mark.asyncio
async def test_record_successful_tool_call_creates_distinct_event(db_session):
    # 21. record_successful_tool_call creates exactly one event.
    ctx = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-rec",
        tool_name="crm.read",
        parameters={},
        session_context={}
    )
    # Check count in sequence event table before record
    async with db_session() as s:
        stmt = select(SequenceEvent).where(SequenceEvent.session_id == "session-rec")
        res_before = await s.execute(stmt)
        assert len(res_before.scalars().all()) == 0

        # Record success
        await SequenceRepository.record_successful_tool_call_from_context(s, ctx)

    # Check count after record
    async with db_session() as s:
        stmt = select(SequenceEvent).where(SequenceEvent.session_id == "session-rec")
        res_after = await s.execute(stmt)
        assert len(res_after.scalars().all()) == 1

@pytest.mark.asyncio
async def test_concurrency_isolation(db_session):
    # 25. Two concurrent operations in the same session must not corrupt state.
    # Dependent tool cannot observe an uncommitted predecessor as completed.
    rule = SequenceRule()
    policy = get_scope_policy()
    context = ToolInvocationContext(
        agent_id="agent-A",
        session_id="session-concurrent",
        tool_name="email.send",
        parameters={},
        session_context={}
    )

    async with db_session() as session_write:
        # Start writing predecessor "crm.read" in session_write, flush but do NOT commit
        event = SequenceEvent(
            session_id="session-concurrent",
            agent_id="agent-A",
            tool_name="crm.read",
            timestamp=datetime.now(timezone.utc)
        )
        session_write.add(event)
        await session_write.flush()

        # In another session context (session_read), run SequenceRule evaluation for "email.send"
        # Standard database isolation hides uncommitted writes, so it must return passed=False
        async with db_session() as session_read:
            res = await rule.evaluate(context, policy, session_read)
            assert res.passed is False

        # Commit write session
        await session_write.commit()

    # Now that it's committed, a new checking reader must see it!
    async with db_session() as session_read2:
        res2 = await rule.evaluate(context, policy, session_read2)
        assert res2.passed is True
