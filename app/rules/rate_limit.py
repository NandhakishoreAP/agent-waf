from datetime import datetime, timezone, timedelta
import logging
from sqlalchemy import select, func, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.rules.engine import BaseRule, RuleEvaluation, ToolInvocationContext
from app.schemas import WAFPolicy
from app.models import RateLimitEvent, Agent

logger = logging.getLogger("agent_waf.rules.rate_limit")

class RateLimitRule(BaseRule):
    async def evaluate(
        self, 
        context: ToolInvocationContext, 
        policy: WAFPolicy, 
        db: AsyncSession
    ) -> RuleEvaluation:
        # Time handling: We use timezone-aware UTC timestamps consistently
        now = datetime.now(timezone.utc)
        
        # 1. Matching policy for the tool
        rate_limit_cfg = None
        for r in policy.rate_limits:
            if r.tool == context.tool_name:
                rate_limit_cfg = r
                break
                
        if not rate_limit_cfg:
            return RuleEvaluation(
                rule="rate_limit",
                passed=True,
                reason=f"No rate limit configured for tool '{context.tool_name}'"
            )
            
        max_calls = rate_limit_cfg.max_calls
        window_seconds = rate_limit_cfg.window_seconds
        cutoff = now - timedelta(seconds=window_seconds)
        
        # 2. Concurrency-safe check and record transaction
        try:
            # We use a database transaction to ensure atomicity
            async with db.begin_nested() if db.in_transaction() else db.begin():
                # Concurrency safety:
                # We perform an UPDATE statement mutating a Timestamp field on the associated Agent row.
                # Unlike SELECT ... FOR UPDATE (not supported in SQLite), database engines executing an actual
                # UPDATE statement are forced to acquire a write lock:
                # - SQLite: immediately locks the database file for writing (serialising other write transactions).
                # - PostgreSQL: locks the row, making other transactions block until this one commits.
                # This achieves database-level locking and concurrency safety database-agnostically!
                lock_stmt = (
                    update(Agent)
                    .where(Agent.agent_id == context.agent_id)
                    .values(created_at=now)
                )
                lock_result = await db.execute(lock_stmt)
                if lock_result.rowcount == 0:
                    # Fail-closed if the agent id is invalid or not registered in the system
                    logger.warning(f"Rate Limiter failed: Agent '{context.agent_id}' does not exist in DB.")
                    return RuleEvaluation(
                        rule="rate_limit",
                        passed=False,
                        reason="Rate limiter evaluation failed: Agent not registered"
                    )
                
                # Cleanup expired events for this specific agent + tool
                cleanup_stmt = delete(RateLimitEvent).where(
                    RateLimitEvent.agent_id == context.agent_id,
                    RateLimitEvent.tool_name == context.tool_name,
                    RateLimitEvent.timestamp < cutoff
                )
                await db.execute(cleanup_stmt)
                
                # Count current calls in the window
                count_stmt = (
                    select(func.count(RateLimitEvent.id))
                    .where(
                        RateLimitEvent.agent_id == context.agent_id,
                        RateLimitEvent.tool_name == context.tool_name,
                        RateLimitEvent.timestamp >= cutoff
                    )
                )
                count_result = await db.execute(count_stmt)
                current_calls = count_result.scalar() or 0
                
                if current_calls >= max_calls:
                    return RuleEvaluation(
                        rule="rate_limit",
                        passed=False,
                        reason=f"Rate limit exceeded: {max_calls} calls in {window_seconds} seconds"
                    )
                
                # Increment/record call event
                new_event = RateLimitEvent(
                    agent_id=context.agent_id,
                    tool_name=context.tool_name,
                    timestamp=now
                )
                db.add(new_event)
                
            return RuleEvaluation(
                rule="rate_limit",
                passed=True,
                reason="Rate limit not exceeded"
            )
            
        except Exception as e:
            logger.error(f"Rate Limiter encountered database exception: {e}", exc_info=True)
            # Fail closed: return failed evaluation to block for security reasons
            return RuleEvaluation(
                rule="rate_limit",
                passed=False,
                reason="Rate limiter evaluation failed due to system error"
            )
