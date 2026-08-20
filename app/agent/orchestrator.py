import json
import logging
from typing import Any, Dict, List, Optional
from app.config import settings
from app.agent.client import WAFClient, WAFResult
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

    def _validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[str]:
        """
        Validates the arguments format and required keys locally as an untrusted client validation check.
        Returns error string if invalid, None otherwise.
        """
        schemas = {t["name"]: t for t in self.tools}
        if tool_name not in schemas:
            return f"Unknown tool: {tool_name}"

        schema = schemas[tool_name]
        parameters_spec = schema.get("parameters", {})
        required_keys = parameters_spec.get("required", [])
        properties = parameters_spec.get("properties", {})

        # Check required fields
        for rk in required_keys:
            if rk not in arguments:
                return f"Missing required parameter: {rk}"

        # Check parameter types
        for k, v in arguments.items():
            if k in properties:
                expected_type = properties[k].get("type")
                if expected_type == "string" and not isinstance(v, str):
                    return f"Parameter {k} must be string"
                elif expected_type == "integer" and not isinstance(v, int):
                    return f"Parameter {k} must be integer"
                elif expected_type == "object" and not isinstance(v, dict):
                    return f"Parameter {k} must be object"
                elif expected_type == "array" and not isinstance(v, list):
                    return f"Parameter {k} must be list"
        
        return None

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
                    tool_name = tc.get("name")
                    arguments = tc.get("arguments", {})
                    call_id = tc.get("id")

                    # 1. First run syntactic validation check locally (as required by prompt)
                    validation_err = self._validate_tool_call(tool_name, arguments)
                    
                    if validation_err:
                        logger.warning(f"Tool call locally failed validation: {validation_err}")
                        # Even if locally failed, we must route it to WAF client to enforce the fail-closed boundary
                        # (WAF client will handle unknown/malformed tools via the registry)

                    # 2. Invoke WAF Client to securely intermediate tool call (no direct tool execution)
                    waf_res = await self.waf_client.invoke(
                        agent_id=self.agent_id,
                        session_id=self.session_id,
                        tool=tool_name,
                        parameters=arguments,
                        correlation_id=self.correlation_id
                    )

                    # Gather the execution records
                    call_record = {
                        "id": call_id,
                        "tool": tool_name,
                        "parameters": arguments,
                        "allowed": waf_res.allowed,
                        "disposition": waf_res.disposition
                    }

                    if waf_res.allowed:
                        logger.info(f"WAF ALLOWED invocation of tool `{tool_name}` successfully.")
                        tool_calls_made.append(call_record)
                        tool_result_content = json.dumps(waf_res.tool_result)
                    else:
                        logger.info(f"WAF BLOCKED invocation of tool `{tool_name}`: {waf_res.error}")
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
                                "name": tool_name,
                                "arguments": json.dumps(arguments)
                            }
                        }]
                    })

                    messages.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": tool_name,
                        "content": tool_result_content
                    })

                    if not waf_res.allowed:
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
