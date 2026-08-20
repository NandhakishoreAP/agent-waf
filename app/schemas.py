from datetime import datetime
from typing import Any, Optional, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
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
    correlation_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Policy Pydantic Models for Milestone 3 ---

class RateLimitPolicy(BaseModel):
    tool: str = Field(..., min_length=1, description="Tool name cannot be empty")
    max_calls: int = Field(..., gt=0, description="max_calls must be greater than 0")
    window_seconds: int = Field(..., gt=0, description="window_seconds must be greater than 0")

class ParameterValidationPolicy(BaseModel):
    tool: str = Field(..., min_length=1, description="Tool name cannot be empty")
    blocklist_patterns: list[str] = Field(..., description="blocklist_patterns must be a list")
    max_param_length: int = Field(..., gt=0, description="max_param_length must be greater than 0")

    @field_validator("blocklist_patterns")
    @classmethod
    def validate_patterns(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list):
            raise ValueError("blocklist_patterns must be a list")
        for pattern in v:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError("each pattern must be a non-empty string")
        return v

class DataScopePolicy(BaseModel):
    tool: str = Field(..., min_length=1, description="Tool name cannot be empty")
    rule: str = Field(..., min_length=1, description="Rule cannot be empty")

class SequencePolicy(BaseModel):
    tool: str = Field(..., min_length=1, description="Tool name cannot be empty")
    requires_prior: list[str] = Field(..., description="requires_prior must contain at least one tool")

    @field_validator("requires_prior")
    @classmethod
    def validate_requires_prior(cls, v: list[str]) -> list[str]:
        if not isinstance(v, list) or len(v) == 0:
            raise ValueError("requires_prior must contain at least one tool")
        for t in v:
            if not isinstance(t, str) or not t.strip():
                raise ValueError("tool in requires_prior cannot be empty")
        return v

class WAFPolicy(BaseModel):
    policy_version: str = Field(..., min_length=1, description="policy_version cannot be empty")
    mode: Literal["enforce", "shadow"]
    rate_limits: list[RateLimitPolicy] = Field(default_factory=list)
    parameter_validation: list[ParameterValidationPolicy] = Field(default_factory=list)
    data_scope: list[DataScopePolicy] = Field(default_factory=list)
    sequence_rules: list[SequencePolicy] = Field(default_factory=list)

class WafInvokeRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=255, description="Client-claimed agent ID")
    session_id: str = Field(..., min_length=1, max_length=255, description="Session ID tracking")
    tool: str = Field(..., min_length=1, max_length=255, description="Tool name requested")
    parameters: dict = Field(default_factory=dict, description="Tool parameters context")

    model_config = ConfigDict(extra="forbid")

class WafInvokeResponse(BaseModel):
    allowed: bool
    agent_id: str
    session_id: str
    tool: str
    disposition: str
    rules: list = Field(default_factory=list)
    tool_result: Optional[Any] = None
    correlation_id: Optional[str] = None


# --- Observability API Response Models ---

class ObservabilitySummaryResponse(BaseModel):
    window: str
    total_calls: int
    allowed_calls: int
    blocked_calls: int
    block_rate: float
    active_agents: int

class TimeseriesDataPoint(BaseModel):
    timestamp: str
    allowed: int
    blocked: int

class ToolStat(BaseModel):
    tool: str
    total: int
    allowed: int
    blocked: int

class AgentStat(BaseModel):
    agent_id: str
    total: int
    allowed: int
    blocked: int

class RuleStat(BaseModel):
    rule: str
    blocks: int

class RecentWafEvent(BaseModel):
    id: str
    timestamp: datetime
    agent_id: str
    session_id: str
    tool: str
    parameters_sanitized: Any
    disposition: str
    blocking_rule: Optional[str] = None
    correlation_id: Optional[str] = None
    latency_ms: Optional[int] = None
    allowed: bool
