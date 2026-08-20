import json
import logging
from typing import Any, Dict, List, Optional
from app.config import settings
from app.agent.client import WAFClient, WAFResult
from app.schemas.tool_call_spec import ToolCallSpec
from app.agent.providers import LLMProvider

logger = logging.getLogger("agent_waf.agent.orchestrator")

TOOL_SCHEMAS = [
    {
        "name": "crm.read",
        "description": "Read CRM information for a customer",
        "parameters": {
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "The unique ID of the customer record to retrieve"
                }
            },
            "required": ["customer_id"]
        }
    },
    {
        "name": "email.send",
        "description": "Send email alert notifications to recipients",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {
                    "type": "string",
                    "description": "Recipient email address"
                },
                "subject": {
                    "type": "string",
                    "description": "Subject of the email"
                },
                "body": {
                    "type": "string",
                    "description": "Raw string content body of the email message"
                }
            },
            "required": ["to", "subject", "body"]
        }
    },
    {
        "name": "db.backup_check",
        "description": "Check status of the last database backup",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "db.delete",
        "description": "Delete database records safely by target counts",
        "parameters": {
            "type": "object",
            "properties": {
                "record_count": {
                    "type": "integer",
                    "description": "Number of records to delete"
                }
            },
            "required": ["record_count"]
        }
    }
]

class AgentRunResult:
    def __init__(
        self,
        agent_id: str,
        session_id: str,
        response: str,
        tool_calls: List[Dict[str, Any]],
        blocked_calls: List[Dict[str, Any]],
        status: str = "success"
    ):
        self.agent_id = agent_id
        self.session_id = session_id
        self.response = response
        self.tool_calls = tool_calls
        self.blocked_calls = blocked_calls
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "response": self.response,
            "tool_calls": self.tool_calls,
            "blocked_calls": self.blocked_calls,
            "status": self.status
        }

class Agent:
    def __init__(
        self,
        agent_id: str,
        session_id: str,
        llm_provider: LLMProvider,
        waf_client: WAFClient,
        max_steps: Optional[int] = None,
        correlation_id: Optional[str] = None
    ):
        self.agent_id = agent_id
        self.session_id = session_id
        self.llm_provider = llm_provider
        self.waf_client = waf_client
        self.max_steps = max_steps or settings.MAX_AGENT_STEPS
        self.tools = TOOL_SCHEMAS
        self.correlation_id = correlation_id



    async def run(self, task: str) -> AgentRunResult:
        messages = [
            {"role": "system", "content": "You are a professional enterprise system assistant. Use the provided tools to run tasks securely."},
            {"role": "user", "content": task}
        ]

        steps = 0
        tool_calls_made = []
        blocked_calls = []
        final_answer = ""
        loop_status = "success"

        while steps < self.max_steps:
            steps += 1
            logger.info(f"Agent Loop Step {steps}/{self.max_steps}")
            
            try:
                llm_response = await self.llm_provider.generate(messages, self.tools)
            except Exception as e:
                logger.error(f"LLM generation failed: {e}", exc_info=True)
                return AgentRunResult(
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    response=f"Error: LLM provider failed during conversation orchestration - {str(e)}",
                    tool_calls=tool_calls_made,
                    blocked_calls=blocked_calls,
                    status="llm_error"
                )

            # Case 1: Final Text Response
            if llm_response.get("type") == "text":
                final_answer = llm_response.get("content", "")
                break

            # Case 2: Tool Calls Request
            elif llm_response.get("type") == "tool_calls":
                tool_calls = llm_response.get("tool_calls", [])
                
                # Check for empty tool call lists
                if not tool_calls:
                    final_answer = "No actions taken by the model."
                    break

                for tc in tool_calls:
                    # Validate tool call using ToolCallSpec model
                    try:
                        spec = ToolCallSpec(
                            tool=tc.get("name"),
                            parameters=tc.get("arguments", {})
                        )
                        call_id = tc.get("id")
                    except Exception as ve:
                        validation_err = str(ve)
                        logger.warning(f"Tool call validation error: {validation_err}")
                        # Record as blocked due to validation failure
                        blocked_calls.append({
                            "id": tc.get("id"),
                            "tool": tc.get("name"),
                            "parameters": tc.get("arguments", {}),
                            "allowed": False,
                            "disposition": "BLOCKED",
                            "error": validation_err
                        })
                        # Append a tool message with the error so LLM can react
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc.get("id"),
                            "name": tc.get("name"),
                            "content": f"Error: Invalid tool call specification. {validation_err}"
                        })
                        continue  # skip invoking WAF for this malformed call

                    # Invoke WAF Client to securely intermediate tool call
                    # Invoke WAF Client with tool name and parameters only
                    try:
                        waf_res = await self.waf_client.invoke(
                            agent_id=self.agent_id,
                            session_id=self.session_id,
                            tool=spec.tool,
                            parameters=spec.parameters,
                            correlation_id=self.correlation_id
                        )
                    except Exception as e:
                        logger.error(f"WAF client invocation failed: {e}", exc_info=True)
                        # Treat as blocked with error info
                        waf_res = WAFResult(allowed=False, disposition="BLOCKED", error=str(e))

                    # Gather the execution records
                    call_record = {
                        "id": call_id,
                        "tool": spec.tool,
                        "parameters": spec.parameters,
                        "allowed": waf_res.allowed,
                        "disposition": waf_res.disposition
                    }

                    if waf_res.allowed:
                        logger.info(f"WAF ALLOWED invocation of tool `{spec.tool}` successfully.")
                        tool_calls_made.append(call_record)
                        tool_result_content = json.dumps(waf_res.tool_result)
                    else:
                        logger.info(f"WAF BLOCKED invocation of tool `{spec.tool}`: {waf_res.error}")
                        blocked_calls.append(call_record)
                        tool_result_content = f"Error: Tool call blocked by security policy. Reason: {waf_res.error or 'Blocked by WAF'}"

                    # Append assistant and tool messages to keep chat history intact
                    messages.append({
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": spec.tool,
                                "arguments": json.dumps(spec.parameters)
                            }
                        }]
                    })

                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": spec.tool,
                        "content": tool_result_content
                    })

                    if not waf_res.allowed:
                        # Record blocked call reason if not already captured
                        if not any(bc.get("id") == call_id for bc in blocked_calls):
                            blocked_calls.append({
                                "id": call_id,
                                "tool": spec.tool,
                                "parameters": spec.parameters,
                                "allowed": False,
                                "disposition": waf_res.disposition,
                                "error": getattr(waf_res, "error", "Blocked by WAF")
                            })
                        final_answer = tool_result_content
                        loop_status = "blocked"
                        break

                if loop_status == "blocked":
                    break

                # Proceed to next generation step with appended tool context
                continue

            else:
                logger.error(f"Received unknown LLM response type: {llm_response}")
                loop_status = "error"
                final_answer = "Error: Invalid response format from LLM provider."
                break

        # Check loop step overflow
        if steps >= self.max_steps and not final_answer:
            logger.warning(f"Agent exceeded maximum steps limit of {self.max_steps}")
            loop_status = "max_steps_exceeded"
            final_answer = "Error: Maximum execution steps limit exceeded. Aborting."

        return AgentRunResult(
            agent_id=self.agent_id,
            session_id=self.session_id,
            response=final_answer,
            tool_calls=tool_calls_made,
            blocked_calls=blocked_calls,
            status=loop_status
        )
