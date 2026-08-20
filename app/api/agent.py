import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.agent.client import WAFClient
from app.agent.providers import LLMProvider, OpenAIProvider, TestLLMProvider
from app.agent.orchestrator import Agent
from app.config import settings

logger = logging.getLogger("agent_waf.api.agent")
router = APIRouter()

class AgentRunRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=255, description="The identity of the triggering agent")
    session_id: str = Field(..., min_length=1, max_length=255, description="The tracking session identity context")
    task: str = Field(..., min_length=1, max_length=2000, description="The natural language task description for the agent")

    model_config = ConfigDict(extra="forbid")

class AgentRunResponse(BaseModel):
    agent_id: str
    session_id: str
    response: str
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    blocked_calls: List[Dict[str, Any]] = Field(default_factory=list)
    status: str
    correlation_id: Optional[str] = None

# Dependency injection helpers
def get_llm_provider() -> LLMProvider:
    if settings.LLM_PROVIDER == "openai":
        return OpenAIProvider()
    return TestLLMProvider()

def get_waf_client() -> WAFClient:
    return WAFClient(
        base_url=settings.AGENT_WAF_URL,
        timeout=settings.AGENT_WAF_TIMEOUT_SECONDS
    )

@router.post(
    "/agent/run",
    response_model=AgentRunResponse,
    description="Orchestrates a natural language task using the real LLM or test provider, routing all tool calls through WAF.",
    responses={
        400: {"description": "Invalid input formatting"},
        500: {"description": "Internal error executing agent loop"}
    }
)
async def run_agent(
    request: Request,
    body: AgentRunRequest,
    llm_provider: LLMProvider = Depends(get_llm_provider),
    waf_client: WAFClient = Depends(get_waf_client)
) -> Any:
    # Get/Validate correlation ID from request state (or headers)
    corr_id = getattr(request.state, "correlation_id", None)
    if not corr_id:
        corr_id = request.headers.get("X-Correlation-ID")

    # Build isolated Agent context for the request (concurrency safety)
    agent_instance = Agent(
        agent_id=body.agent_id,
        session_id=body.session_id,
        llm_provider=llm_provider,
        waf_client=waf_client,
        correlation_id=corr_id
    )

    logger.info(f"Agent router received execution request: agent_id={body.agent_id}, session_id={body.session_id}")
    
    # Process the agent loop reasoning steps
    run_result = await agent_instance.run(body.task)

    return {
        "agent_id": run_result.agent_id,
        "session_id": run_result.session_id,
        "response": run_result.response,
        "tool_calls": run_result.tool_calls,
        "blocked_calls": run_result.blocked_calls,
        "status": run_result.status,
        "correlation_id": corr_id
    }
