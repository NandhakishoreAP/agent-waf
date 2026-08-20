import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, case, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db_session
from app.config import settings
from app.models import ToolCallLog, DispositionEnum
from app.observability.publisher import subscribe, unsubscribe
from app.schemas import (
    ObservabilitySummaryResponse,
    TimeseriesDataPoint,
    ToolStat,
    AgentStat,
    RuleStat,
    RecentWafEvent
)

logger = logging.getLogger("agent_waf.api.observability")
router = APIRouter(prefix="/api/observability", tags=["observability"])

def get_time_threshold(window: str) -> datetime:
    """Calculates UTC threshold timestamp based on sliding time window."""
    now = datetime.now(timezone.utc)
    if window == "5m":
        return now - timedelta(minutes=5)
    elif window == "15m":
        return now - timedelta(minutes=15)
    elif window == "1h":
        return now - timedelta(hours=1)
    elif window == "24h":
        return now - timedelta(hours=24)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time window format: {window}. Supported windows: 5m, 15m, 1h, 24h"
        )

@router.get("/summary", response_model=ObservabilitySummaryResponse)
async def get_summary(
    window: str = Query("24h", pattern="^(5m|15m|1h|24h)$"),
    db: AsyncSession = Depends(get_db_session)
):
    """Retrieve WAF summary metrics for a specific time window."""
    try:
        threshold = get_time_threshold(window)
        
        # 1. Total Calls
        stmt_total = select(func.count()).select_from(ToolCallLog).where(ToolCallLog.timestamp >= threshold)
        total_calls = await db.scalar(stmt_total) or 0
        
        # 2. Allowed Calls
        stmt_allowed = select(func.count()).select_from(ToolCallLog).where(
            ToolCallLog.timestamp >= threshold,
            ToolCallLog.final_disposition == DispositionEnum.ALLOWED
        )
        allowed_calls = await db.scalar(stmt_allowed) or 0
        
        # 3. Blocked Calls (any disposition that is not Allowed)
        blocked_calls = total_calls - allowed_calls
        block_rate = float(blocked_calls) / total_calls if total_calls > 0 else 0.0
        
        # 4. Active unique agents
        stmt_agents = select(func.count(func.distinct(ToolCallLog.agent_id))).where(ToolCallLog.timestamp >= threshold)
        active_agents = await db.scalar(stmt_agents) or 0

        return ObservabilitySummaryResponse(
            window=window,
            total_calls=total_calls,
            allowed_calls=allowed_calls,
            blocked_calls=blocked_calls,
            block_rate=round(block_rate, 4),
            active_agents=active_agents
        )
    except Exception as e:
        logger.error(f"Summary metrics retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve summary metrics")

@router.get("/timeseries", response_model=List[TimeseriesDataPoint])
async def get_timeseries(
    window: str = Query("24h", pattern="^(5m|15m|1h|24h)$"),
    db: AsyncSession = Depends(get_db_session)
):
    """Provides time-aggregated timeseries metrics for graph visualizations."""
    try:
        threshold = get_time_threshold(window)
        is_sqlite = db.bind.dialect.name == "sqlite"

        # Determine SQL database-native aggregation expression
        if is_sqlite:
            if window in ("5m", "15m", "1h"):
                # Group by minute
                bucket_expr = func.strftime("%Y-%m-%dT%H:%M:00Z", ToolCallLog.timestamp)
            else:
                # Group by hour
                bucket_expr = func.strftime("%Y-%m-%dT%H:00:00Z", ToolCallLog.timestamp)
        else:
            # PostgreSQL
            if window in ("5m", "15m", "1h"):
                bucket_expr = func.to_char(func.date_trunc("minute", ToolCallLog.timestamp), "YYYY-MM-DD\"T\"HH24:MI:00\"Z\"")
            else:
                bucket_expr = func.to_char(func.date_trunc("hour", ToolCallLog.timestamp), "YYYY-MM-DD\"T\"HH24:00:00\"Z\"")

        stmt = (
            select(
                bucket_expr.label("bucket"),
                func.sum(case((ToolCallLog.final_disposition == DispositionEnum.ALLOWED, 1), else_=0)).label("allowed"),
                func.sum(case((ToolCallLog.final_disposition != DispositionEnum.ALLOWED, 1), else_=0)).label("blocked")
            )
            .where(ToolCallLog.timestamp >= threshold)
            .group_by(bucket_expr)
            .order_by(bucket_expr)
        )
        
        res = await db.execute(stmt)
        data_points = []
        for row in res.all():
            data_points.append(TimeseriesDataPoint(
                timestamp=row.bucket,
                allowed=row.allowed or 0,
                blocked=row.blocked or 0
            ))
        return data_points
    except Exception as e:
        logger.error(f"Timeseries retrieval failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve timeseries metrics")

@router.get("/tools", response_model=List[ToolStat])
async def get_tool_statistics(
    window: str = Query("24h", pattern="^(5m|15m|1h|24h)$"),
    db: AsyncSession = Depends(get_db_session)
):
    """Get metrics grouped by tool name, sorted by traffic volume."""
    try:
        threshold = get_time_threshold(window)
        stmt = (
            select(
                ToolCallLog.tool_name.label("tool"),
                func.count().label("total"),
                func.sum(case((ToolCallLog.final_disposition == DispositionEnum.ALLOWED, 1), else_=0)).label("allowed"),
                func.sum(case((ToolCallLog.final_disposition != DispositionEnum.ALLOWED, 1), else_=0)).label("blocked")
            )
            .where(ToolCallLog.timestamp >= threshold)
            .group_by(ToolCallLog.tool_name)
            .order_by(desc("total"))
        )
        
        res = await db.execute(stmt)
        return [
            ToolStat(
                tool=row.tool,
                total=row.total or 0,
                allowed=row.allowed or 0,
                blocked=row.blocked or 0
            ) for row in res.all()
        ]
    except Exception as e:
        logger.error(f"Tool statistics failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve tool statistics")

@router.get("/agents", response_model=List[AgentStat])
async def get_agent_statistics(
    window: str = Query("24h", pattern="^(5m|15m|1h|24h)$"),
    db: AsyncSession = Depends(get_db_session)
):
    """Get metrics grouped by agent ID, sorted by total volume."""
    try:
        threshold = get_time_threshold(window)
        stmt = (
            select(
                ToolCallLog.agent_id.label("agent_id"),
                func.count().label("total"),
                func.sum(case((ToolCallLog.final_disposition == DispositionEnum.ALLOWED, 1), else_=0)).label("allowed"),
                func.sum(case((ToolCallLog.final_disposition != DispositionEnum.ALLOWED, 1), else_=0)).label("blocked")
            )
            .where(ToolCallLog.timestamp >= threshold)
            .group_by(ToolCallLog.agent_id)
            .order_by(desc("total"))
        )
        
        res = await db.execute(stmt)
        return [
            AgentStat(
                agent_id=row.agent_id,
                total=row.total or 0,
                allowed=row.allowed or 0,
                blocked=row.blocked or 0
            ) for row in res.all()
        ]
    except Exception as e:
        logger.error(f"Agent statistics failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve agent statistics")

@router.get("/blocks", response_model=List[RuleStat])
async def get_rule_blocking_statistics(
    window: str = Query("24h", pattern="^(5m|15m|1h|24h)$"),
    db: AsyncSession = Depends(get_db_session)
):
    """Retrieve statistics of which rules triggered blocks."""
    try:
        threshold = get_time_threshold(window)
        stmt = (
            select(ToolCallLog.rule_evaluations)
            .where(
                ToolCallLog.timestamp >= threshold,
                ToolCallLog.final_disposition != DispositionEnum.ALLOWED
            )
        )
        
        res = await db.execute(stmt)
        rule_counts = {
            "rate_limit": 0,
            "parameter_validation": 0,
            "data_scope": 0,
            "sequence": 0
        }
        
        for rule_evals_json in res.scalars():
            if isinstance(rule_evals_json, list):
                for ev in rule_evals_json:
                    if isinstance(ev, dict) and not ev.get("passed"):
                        r_name = ev.get("rule")
                        if r_name in rule_counts:
                            rule_counts[r_name] += 1

        return [
            RuleStat(rule=k, blocks=v)
            for k, v in rule_counts.items()
        ]
    except Exception as e:
        logger.error(f"Rule blocking statistics failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve rule statistics")

@router.get("/events", response_model=List[RecentWafEvent])
async def get_recent_events(
    window: str = Query("24h", pattern="^(5m|15m|1h|24h)$"),
    agent_id: Optional[str] = Query(None, min_length=1),
    tool: Optional[str] = Query(None, min_length=1),
    disposition: Optional[str] = Query(None, pattern="^(ALLOWED|BLOCKED|SHADOW_BLOCKED)$"),
    blocking_rule: Optional[str] = Query(None, min_length=1),
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session)
):
    """Returns paginated, filtered list of WAF security events."""
    try:
        # Enforce server-side maximum page checks
        max_size = settings.OBSERVABILITY_MAX_PAGE_SIZE
        if limit > max_size:
            logger.warning(f"Client requested page size limit={limit} exceeding max capacity. Enforcing limit={max_size}")
            limit = max_size

        threshold = get_time_threshold(window)
        stmt = select(ToolCallLog).where(ToolCallLog.timestamp >= threshold)
        
        if agent_id:
            stmt = stmt.where(ToolCallLog.agent_id == agent_id)
        if tool:
            stmt = stmt.where(ToolCallLog.tool_name == tool)
        if disposition:
            stmt = stmt.where(ToolCallLog.final_disposition == disposition)

        stmt = stmt.order_by(ToolCallLog.timestamp.desc())
        
        # Determine query limit. If filtering by blocking_rule, we must fetch
        # and filter in memory, so we fetch slightly larger batch, but still page-bound.
        if blocking_rule:
            # Fetch a larger chunk to allow post-filtering in code
            stmt = stmt.limit(limit * 5).offset(offset)
        else:
            stmt = stmt.limit(limit).offset(offset)

        res = await db.execute(stmt)
        events = []
        
        for db_log in res.scalars():
            blocking_r = None
            evals = db_log.rule_evaluations or []
            disp = db_log.final_disposition.value if hasattr(db_log.final_disposition, "value") else str(db_log.final_disposition)
            
            if disp != "ALLOWED":
                for val in evals:
                    if isinstance(val, dict) and not val.get("passed"):
                        blocking_r = val.get("rule")
                        break
            
            # Filter matches by blocking rule
            if blocking_rule and blocking_r != blocking_rule:
                continue

            events.append(RecentWafEvent(
                id=db_log.id,
                timestamp=db_log.timestamp,
                agent_id=db_log.agent_id,
                session_id=db_log.session_id,
                tool=db_log.tool_name,
                parameters_sanitized=db_log.parameters_sanitized,
                disposition=disp,
                blocking_rule=blocking_r,
                correlation_id=db_log.correlation_id,
                latency_ms=db_log.latency_ms,
                allowed=(disp == "ALLOWED")
            ))

        # Handle page boundaries for memory filtered list
        if blocking_rule:
            return events[:limit]
        return events
    except Exception as e:
        logger.error(f"Failed to query recent WAF events: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve recent events")

@router.get("/stream")
async def sse_stream(request: Request):
    """
    Server-Sent Events endpoint implementing real-time traffic updates.
    Returns HTTP EventSource stream.
    """
    if not settings.OBSERVABILITY_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Observability stream subsystem is disabled by settings configuration."
        )

    queue = await subscribe()

    async def event_generator():
        try:
            while True:
                # Detect client disconnect early
                if await request.is_disconnected():
                    logger.debug("SSE client disconnected from streaming route.")
                    break
                try:
                    # Receive event or trigger heartbeat keepalive
                    event_data = await asyncio.wait_for(
                        queue.get(),
                        timeout=float(settings.SSE_HEARTBEAT_SECONDS)
                    )
                    yield f"data: {json.dumps(event_data)}\n\n"
                except asyncio.TimeoutError:
                    # Periodic heartbeat to maintain connection
                    yield ": heartbeat\n\n"
        except asyncio.CancelledError:
            logger.debug("SSE stream generator execution cancelled.")
        finally:
            await unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
