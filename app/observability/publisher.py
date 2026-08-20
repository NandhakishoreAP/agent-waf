import asyncio
import json
import logging
from typing import Any, Dict, Set
from app.config import settings

logger = logging.getLogger("agent_waf.observability.publisher")

# Set of active async queues, one per connected client SSE stream
_subscribers: Set[asyncio.Queue] = set()
_lock = asyncio.Lock()

async def subscribe() -> asyncio.Queue:
    """Subscribe a new client queue to WAF audit events."""
    queue = asyncio.Queue(maxsize=100)  # Bounded resource usage: limit backlog size
    async with _lock:
        _subscribers.add(queue)
    logger.debug(f"New SSE client connected. Active subscribers count: {len(_subscribers)}")
    return queue

async def unsubscribe(queue: asyncio.Queue) -> None:
    """Unsubscribe a client queue on disconnect."""
    async with _lock:
        _subscribers.discard(queue)
    logger.debug(f"SSE client disconnected. Active subscribers count: {len(_subscribers)}")

async def publish_event(db_log: Any) -> None:
    """
    Publish a sanitized WAF audit event to all active SSE subscribers.
    Takes a ToolCallLog database model record.
    """
    try:
        # 1. Inspect and extract rules evaluation to identify which rule caused blocking
        blocking_rule = None
        evals = db_log.rule_evaluations or []
        disp = db_log.final_disposition.value if hasattr(db_log.final_disposition, "value") else str(db_log.final_disposition)
        
        if disp != "ALLOWED":
            for val in evals:
                if isinstance(val, dict) and not val.get("passed"):
                    blocking_rule = val.get("rule")
                    break

        # 2. Build the event payload
        event_data = {
            "id": db_log.id,
            "timestamp": db_log.timestamp.isoformat() if db_log.timestamp else None,
            "agent_id": db_log.agent_id,
            "session_id": db_log.session_id,
            "tool": db_log.tool_name,
            "parameters_sanitized": db_log.parameters_sanitized,
            "disposition": disp,
            "blocking_rule": blocking_rule,
            "correlation_id": db_log.correlation_id,
            "latency_ms": db_log.latency_ms,
            "allowed": (disp == "ALLOWED")
        }

        # 3. Publish to all queues
        async with _lock:
            for queue in list(_subscribers):
                try:
                    queue.put_nowait(event_data)
                except asyncio.QueueFull:
                    # Discard oldest event if queue overflows to avoid blocking publisher
                    try:
                        queue.get_nowait()
                        queue.put_nowait(event_data)
                    except Exception:
                        pass
    except Exception as e:
        logger.error(f"Error publishing SSE WAF event: {e}", exc_info=True)
