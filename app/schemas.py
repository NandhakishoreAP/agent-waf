from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict
from app.models import DispositionEnum

class AgentCreate(BaseModel):
    agent_id: Optional[str] = None  # Optional custom ID (e.g. support-agent-01)
    name: str
    declared_scope: Any

class AgentResponse(BaseModel):
    agent_id: str
    name: str
    declared_scope: Any
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ToolCallLogResponse(BaseModel):
    id: str
    timestamp: datetime
    agent_id: str
    session_id: str
    tool_name: str
    parameters_sanitized: Any
    rule_evaluations: Any
    final_disposition: DispositionEnum
    latency_ms: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)
