import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db_session
from app.models import SessionContext
from app.rules.engine import RuleEngine, ToolInvocationContext, FinalDisposition
from app.rules.rate_limit import RateLimitRule
from app.rules.param_validation import ParameterValidationRule
from app.rules.data_scope import DataScopeRule
from app.rules.sequence import SequenceRule, SequenceRepository
from app.schemas import WafInvokeRequest, WafInvokeResponse
from app.tools.registry import registry

logger = logging.getLogger("agent_waf.api.waf")
router = APIRouter()

class SessionContextRepository:
    @staticmethod
    async def get_session_context(db: AsyncSession, session_id: str) -> Dict[str, Any]:
        """Fetch trusted session contexts from the database."""
        try:
            stmt = select(SessionContext).where(SessionContext.session_id == session_id)
            res = await db.execute(stmt)
            record = res.scalar_one_or_none()
            if record:
                return {"customer_id": record.customer_id}
        except Exception as e:
            logger.error(f"Database error reading session context: {e}", exc_info=True)

        # Fallback helper mappings for local manual curls and test sessions
        return {}

    @staticmethod
    async def set_session_context(db: AsyncSession, session_id: str, customer_id: str) -> None:
        """Insert or merge a trusted session context."""
        async with db.begin_nested() if db.in_transaction() else db.begin():
            record = SessionContext(session_id=session_id, customer_id=customer_id)
            await db.merge(record)

@router.post(
    "/waf/invoke",
    response_model=WafInvokeResponse,
    responses={
        403: {"model": WafInvokeResponse, "description": "Invocation blocked by WAF security policy"},
        404: {"description": "Requested tool not registered in WAF registry"},
        400: {"description": "Malformed request parameters"}
    }
)
async def invoke_tool(
    request: Request,
    body: WafInvokeRequest,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    # 0. Safety Check: Verify policy is loaded
    policy = getattr(request.app.state, "policy", None)
    if not policy:
        logger.error("WAF invocation rejected: Security policy is not active or loaded.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="WAF security policy is not active"
        )

    # 1. Resolve session context from persistent store (no user masquerading allowed)
    session_context = await SessionContextRepository.get_session_context(db, body.session_id)

    # 2. Build ToolInvocationContext
    context = ToolInvocationContext(
        agent_id=body.agent_id,
        session_id=body.session_id,
        tool_name=body.tool,
        parameters=body.parameters,
        session_context=session_context
    )

    # 3. Check tool registry (protect against dynamic/module import vulnerabilities)
    if not registry.exists(body.tool):
        logger.warning(f"Rejecting client request for unregistered tool: '{body.tool}'")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{body.tool}' not found in registry"
        )

    # 4. Evaluate all security rules (enforce order: rate_limit -> param_validation -> data_scope -> sequence)
    import time
    import uuid
    import re
    
    start_time = time.time()
    CORRELATION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")
    
    corr_id = getattr(request.state, "correlation_id", None)
    if not corr_id:
        h_corr = request.headers.get("X-Correlation-ID")
        if h_corr and CORRELATION_ID_PATTERN.match(h_corr):
            corr_id = h_corr
        else:
            corr_id = str(uuid.uuid4())

    async def write_audit_log(disposition_val: str, rules_list: list, status_code: int):
        try:
            from app.models import ToolCallLog, DispositionEnum
            from app.utils.sanitization import sanitize_parameters
            
            sanitized_params = sanitize_parameters(body.parameters)

            # Match final disposition enum
            if disposition_val == "ALLOWED":
                enum_disp = DispositionEnum.ALLOWED
            elif disposition_val in ("BLOCKED", "TOOL_ERROR"): # Map block/error status securely
                enum_disp = DispositionEnum.BLOCKED
            else:
                enum_disp = DispositionEnum.SHADOW_BLOCKED

            latency = int((time.time() - start_time) * 1000)

            audit_log = ToolCallLog(
                agent_id=body.agent_id,
                session_id=body.session_id,
                tool_name=body.tool,
                parameters_sanitized=sanitized_params,
                rule_evaluations=rules_list,
                final_disposition=enum_disp,
                latency_ms=latency,
                correlation_id=corr_id
            )
            db.add(audit_log)
            await db.commit()

            # Publish event to real-time subscribers
            try:
                from app.observability.publisher import publish_event
                await publish_event(audit_log)
            except Exception as pe:
                logger.error(f"Failed to publish event to stream: {pe}")

        except Exception as ex:
            logger.error(f"Failed to record WAF database audit log: {ex}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security WAF state update failed"
            )

    try:
        engine = RuleEngine(policy, [
            RateLimitRule(),
            ParameterValidationRule(),
            DataScopeRule(),
            SequenceRule()
        ])
        engine_result = await engine.evaluate(context, db)
    except Exception as e:
        logger.error(f"RuleEngine failed closed due to execution runtime error: {e}", exc_info=True)
        # Default safety posture: block if decision rules failed to complete execution
        rules_evals = [
            {
                "rule": "engine",
                "passed": False,
                "reason": f"Internal security validator failure: {str(e)}"
            }
        ]
        await write_audit_log("BLOCKED", rules_evals, 403)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "allowed": False,
                "agent_id": body.agent_id,
                "session_id": body.session_id,
                "tool": body.tool,
                "disposition": "BLOCKED",
                "rules": rules_evals,
                "tool_result": None,
                "correlation_id": corr_id
            }
        )

    rules_evals = [
        {
            "rule": ev.rule,
            "passed": ev.passed,
            "reason": ev.reason
        }
        for ev in engine_result.evaluations
    ]

    # 5. Handle WAF Block response (fail-closed immediately, avoiding tool execution)
    if engine_result.final_disposition in (FinalDisposition.BLOCKED, FinalDisposition.SHADOW_BLOCKED):
        await write_audit_log("BLOCKED", rules_evals, 403)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "allowed": False,
                "agent_id": body.agent_id,
                "session_id": body.session_id,
                "tool": body.tool,
                "disposition": engine_result.final_disposition.value,
                "rules": rules_evals,
                "tool_result": None,
                "correlation_id": corr_id
            }
        )

    # 6. Execute registered tool handler safely catching exceptions
    try:
        tool_result = await registry.execute(body.tool, body.parameters)
    except Exception as e:
        logger.error(f"Registered tool '{body.tool}' handler raised an runtime exception: {e}", exc_info=True)
        # TOOL_ERROR: Allowed to execute, but tool failed. Do NOT record sequence event context.
        await write_audit_log("TOOL_ERROR", rules_evals, 200)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "allowed": True,
                "agent_id": body.agent_id,
                "session_id": body.session_id,
                "tool": body.tool,
                "disposition": "TOOL_ERROR",
                "rules": rules_evals,
                "tool_result": None,
                "correlation_id": corr_id
            }
        )

    # 7. Record sequence success event only *after* successful execution is complete
    try:
        await SequenceRepository.record_successful_tool_call_from_context(db, context)
    except Exception as e:
        logger.critical(f"Consistent State Error: Sequence record writing failed: {e}", exc_info=True)
        # Fail closed on database database/state persistence failure
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security WAF state update failed"
        )

    # Write audit log to database on successful allowance path
    await write_audit_log("ALLOWED", rules_evals, 200)

    # 8. Return successful response
    return {
        "allowed": True,
        "agent_id": body.agent_id,
        "session_id": body.session_id,
        "tool": body.tool,
        "disposition": "ALLOWED",
        "rules": rules_evals,
        "tool_result": tool_result,
        "correlation_id": corr_id
    }
