import pytest
import asyncio
from app.agent.orchestrator import Agent
from app.agent.providers import TestLLMProvider
from app.agent.client import WAFClient, WAFResult
from app.models import DispositionEnum
from app.tools import registry
from unittest.mock import patch

# Simple mock WAF client used in tests
class MockWAFClient:
    def __init__(self, allowed=True, raise_error: Exception | None = None):
        self.allowed = allowed
        self.raise_error = raise_error
        self.invocations = []

    async def invoke(self, agent_id: str, session_id: str, tool: str, parameters: dict, correlation_id: str | None = None) -> WAFResult:
        self.invocations.append((tool, parameters))
        if self.raise_error:
            raise self.raise_error
        return WAFResult(
            allowed=self.allowed,
            disposition="ALLOWED" if self.allowed else "BLOCKED",
            tool_result={"mock": "result"} if self.allowed else None,
            error=None if self.allowed else "policy denied",
        )

@pytest.mark.asyncio
async def test_autonomous_single_allowed_tool():
    agent = Agent(
        agent_id="test-agent-01",
        session_id="test-session-01",
        llm_provider=TestLLMProvider(),
        waf_client=MockWAFClient(allowed=True),
    )
    result = await agent.run("Get CRM information for customer CUST-1001")
    assert result.status == "success"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["tool"] == "crm.read"
    assert result.tool_calls[0]["allowed"] is True
    assert "CRM information retrieved" in result.response
    assert len(result.blocked_calls) == 0

@pytest.mark.asyncio
async def test_autonomous_blocked_tool():
    agent = Agent(
        agent_id="test-agent-01",
        session_id="test-session-01",
        llm_provider=TestLLMProvider(),
        waf_client=MockWAFClient(allowed=False),
    )
    result = await agent.run("Get CRM record customer_id=CUST-9999")
    assert result.status == "blocked"
    assert len(result.tool_calls) == 0
    assert len(result.blocked_calls) == 1
    assert result.blocked_calls[0]["tool"] == "crm.read"
    assert result.blocked_calls[0]["allowed"] is False
    assert "blocked" in result.response.lower()

@pytest.mark.asyncio
async def test_autonomous_multi_step_flow():
    # Provider will emit a sequence_success scenario (two tool calls)
    agent = Agent(
        agent_id="test-agent-01",
        session_id="test-session-01",
        llm_provider=TestLLMProvider(),
        waf_client=MockWAFClient(allowed=True),
    )
    result = await agent.run("sequence_success: check customer and alert")
    assert result.status == "success"
    assert len(result.tool_calls) == 2
    assert result.tool_calls[0]["tool"] == "crm.read"
    assert result.tool_calls[1]["tool"] == "email.send"
    assert all(tc["allowed"] for tc in result.tool_calls)
    assert "Executed sequence successfully" in result.response

@pytest.mark.asyncio
async def test_autonomous_malformed_tool_call():
    agent = Agent(
        agent_id="test-agent-01",
        session_id="test-session-01",
        llm_provider=TestLLMProvider(),
        waf_client=MockWAFClient(allowed=True),
    )
    result = await agent.run("malformed_tool_call: format invalid input parameters")
    # Validation should reject the malformed arguments, resulting in a blocked call
    assert result.status == "blocked"
    assert len(result.tool_calls) == 0
    assert len(result.blocked_calls) == 1
    assert result.blocked_calls[0]["allowed"] is False
    assert "Invalid tool call specification" in result.response

@pytest.mark.asyncio
async def test_autonomous_max_steps():
    # Provider that always returns a simple allowed tool call (crm.read)
    class LoopProvider(TestLLMProvider):
        async def generate(self, messages, tools):
            return {
                "type": "tool_calls",
                "tool_calls": [{
                    "id": "loop-call",
                    "name": "crm.read",
                    "arguments": {"customer_id": "CUST-1001"},
                }],
            }
    # Use a small step limit to finish quickly
    from app.config import settings
    original = settings.MAX_AGENT_STEPS
    settings.MAX_AGENT_STEPS = 3
    try:
        agent = Agent(
            agent_id="test-agent-01",
            session_id="test-session-01",
            llm_provider=LoopProvider(),
            waf_client=MockWAFClient(allowed=True),
        )
        result = await agent.run("loop test")
        assert result.status == "max_steps_exceeded"
        assert "Maximum execution steps limit exceeded" in result.response
    finally:
        settings.MAX_AGENT_STEPS = original

@pytest.mark.asyncio
async def test_autonomous_waf_error():
    # Mock WAF client that raises an exception
    agent = Agent(
        agent_id="test-agent-01",
        session_id="test-session-01",
        llm_provider=TestLLMProvider(),
        waf_client=MockWAFClient(raise_error=Exception("WAF internal error")),
    )
    result = await agent.run("Get CRM information for customer CUST-1001")
    # The orchestrator treats the exception as a blocked call
    assert result.status == "blocked"
    assert len(result.blocked_calls) == 1
    assert result.blocked_calls[0]["allowed"] is False
    assert "WAF internal error" in result.response

@pytest.mark.asyncio
async def test_autonomous_provider_error():
    class BadProvider(TestLLMProvider):
        async def generate(self, messages, tools):
            raise RuntimeError("LLM crashed")
    agent = Agent(
        agent_id="test-agent-01",
        session_id="test-session-01",
        llm_provider=BadProvider(),
        waf_client=MockWAFClient(allowed=True),
    )
    result = await agent.run("any task")
    assert result.status == "llm_error"
    assert "LLM provider failed" in result.response

@pytest.mark.asyncio
async def test_autonomous_security_registry_bypass():
    # Ensure Agent never calls registry.execute directly
    agent = Agent(
        agent_id="test-agent-01",
        session_id="test-session-01",
        llm_provider=TestLLMProvider(),
        waf_client=MockWAFClient(allowed=True),
    )
    with patch.object(registry, "execute", side_effect=RuntimeError("Direct call")) as mock_exec:
        result = await agent.run("Get CRM information for customer CUST-1001")
        # No direct call should have been made
        assert mock_exec.call_count == 0
        assert result.status == "success"
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0]["tool"] == "crm.read"
