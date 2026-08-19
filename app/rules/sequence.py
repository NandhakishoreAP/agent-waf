import logging
from datetime import datetime, timezone
from sqlalchemy import select, and_, exists
from sqlalchemy.ext.asyncio import AsyncSession
from app.rules.engine import BaseRule, RuleEvaluation, ToolInvocationContext
from app.schemas import WAFPolicy
from app.models import SequenceEvent

logger = logging.getLogger("agent_waf.rules.sequence")

class SequenceRepository:
    @staticmethod
    async def has_successful_tool_call(
        db: AsyncSession,
        session_id: str,
        agent_id: str,
        tool_name: str,
        before_timestamp: datetime
    ) -> bool:
        """Checks if a successful invocation of tool_name has occurred in this session prior to before_timestamp."""
        # 1. Identity integrity check: session_id must only be associated with agent_id
        integrity_check = select(SequenceEvent.agent_id).where(
            SequenceEvent.session_id == session_id
        ).limit(1)
        integrity_result = await db.execute(integrity_check)
        existing_agent_id = integrity_result.scalar_one_or_none()
        if existing_agent_id and existing_agent_id != agent_id:
            raise ValueError(f"Identity mismatch: session {session_id} belongs to agent {existing_agent_id}, claimed agent {agent_id}")

        # 2. Check for predecessor event
        query = select(exists().where(
            and_(
                SequenceEvent.session_id == session_id,
                SequenceEvent.agent_id == agent_id,
                SequenceEvent.tool_name == tool_name,
                SequenceEvent.timestamp < before_timestamp
            )
        ))
        res = await db.execute(query)
        return res.scalar() or False

    @staticmethod
    async def record_successful_tool_call(
        db: AsyncSession,
        session_id: str,
        agent_id: str,
        tool_name: str,
        timestamp: datetime
    ) -> None:
        """Atomic recording of a successful execution."""
        # Integrity check: make sure another agent is not hijacking the session
        integrity_check = select(SequenceEvent.agent_id).where(
            SequenceEvent.session_id == session_id
        ).limit(1)
        integrity_result = await db.execute(integrity_check)
        existing_agent_id = integrity_result.scalar_one_or_none()
        if existing_agent_id and existing_agent_id != agent_id:
            raise ValueError(f"Identity mismatch: session {session_id} belongs to agent {existing_agent_id}, claimed agent {agent_id}")

        async with db.begin_nested() if db.in_transaction() else db.begin():
            event = SequenceEvent(
                session_id=session_id,
                agent_id=agent_id,
                tool_name=tool_name,
                timestamp=timestamp
            )
            db.add(event)

    @staticmethod
    async def record_successful_tool_call_from_context(
        db: AsyncSession,
        context: ToolInvocationContext,
        timestamp: datetime = None
    ) -> None:
        if not context.session_id or not context.agent_id or not context.tool_name:
            raise ValueError("All context identity fields (session_id, agent_id, tool_name) are required")
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        await SequenceRepository.record_successful_tool_call(
            db, 
            context.session_id, 
            context.agent_id, 
            context.tool_name, 
            timestamp
        )

    @staticmethod
    async def cleanup_session_data(db: AsyncSession, session_id: str) -> None:
        """Service helper to manually prune sequence events of a session."""
        from sqlalchemy import delete
        async with db.begin_nested() if db.in_transaction() else db.begin():
            stmt = delete(SequenceEvent).where(SequenceEvent.session_id == session_id)
            await db.execute(stmt)

class SequenceRule(BaseRule):
    async def evaluate(
        self, 
        context: ToolInvocationContext, 
        policy: WAFPolicy, 
        db: AsyncSession
    ) -> RuleEvaluation:
        # 1. Identity validation
        if not context.session_id:
            return RuleEvaluation(
                rule="sequence",
                passed=False,
                reason="Required predecessor tool has not successfully completed in this session"
            )
        if not context.agent_id:
            return RuleEvaluation(
                rule="sequence",
                passed=False,
                reason="Required predecessor tool has not successfully completed in this session"
            )

        now = datetime.now(timezone.utc)

        # 2. Policy matching
        matching_rules = []
        for r in policy.sequence_rules:
            if r.tool == context.tool_name or r.tool == "*":
                matching_rules.append(r)

        if not matching_rules:
            return RuleEvaluation(
                rule="sequence",
                passed=True,
                reason="No sequence rule configured for tool"
            )

        # 3. Check requirements
        try:
            for r in matching_rules:
                for req in r.requires_prior:
                    # Enforce predecessor tool check
                    satisfied = await SequenceRepository.has_successful_tool_call(
                        db=db,
                        session_id=context.session_id,
                        agent_id=context.agent_id,
                        tool_name=req,
                        before_timestamp=now
                    )
                    if not satisfied:
                        return RuleEvaluation(
                            rule="sequence",
                            passed=False,
                            reason="Required predecessor tool has not successfully completed in this session"
                        )
        except ValueError as e:
            # Handle identity mismatch cleanly
            logger.warning(f"Identity mismatch in sequence rule check: {e}")
            return RuleEvaluation(
                rule="sequence",
                passed=False,
                reason="Required predecessor tool has not successfully completed in this session"
            )
        except Exception as e:
            logger.error(f"Error evaluating sequence rule database fetch: {e}", exc_info=True)
            # Fail closed on database failure or other exception
            return RuleEvaluation(
                rule="sequence",
                passed=False,
                reason="Required predecessor tool has not successfully completed in this session"
            )

        return RuleEvaluation(
            rule="sequence",
            passed=True,
            reason="Required tool sequence satisfied"
        )
