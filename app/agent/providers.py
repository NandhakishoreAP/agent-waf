import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from openai import AsyncOpenAI
from app.config import settings

logger = logging.getLogger("agent_waf.agent.providers")

class LLMProvider(ABC):
    @abstractmethod
    async def generate(
        self, 
        messages: List[Dict[str, Any]], 
        tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate response or tool calls from the LLM.
        Returns:
            Dict: {"type": "text", "content": "..."} OR 
                  {"type": "tool_calls", "tool_calls": [{"id": "...", "name": "...", "arguments": {...}}]}
        """
        pass

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.OPENAI_API_KEY
        self.model = model or settings.OPENAI_MODEL
        # Initialize client if API Key exists
        self.client = AsyncOpenAI(api_key=self.api_key) if self.api_key else None

    async def generate(
        self, 
        messages: List[Dict[str, Any]], 
        tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not self.client:
            raise ValueError("OpenAI API key is missing. Set the OPENAI_API_KEY environment variable.")

        formatted_tools = None
        if tools:
            formatted_tools = []
            for t in tools:
                formatted_tools.append({
                    "type": "function",
                    "function": t
                })

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=formatted_tools,
                temperature=0.0
            )
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}", exc_info=True)
            raise

        message = response.choices[0].message

        if message.tool_calls:
            calls = []
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except Exception:
                    args = {}
                calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": args
                })
            return {
                "type": "tool_calls",
                "tool_calls": calls
            }

        return {
            "type": "text",
            "content": message.content or ""
        }

class GroqProvider(LLMProvider):
    def __init__(
        self, 
        api_key: str | None = None, 
        model: str | None = None, 
        base_url: str | None = None
    ):
        self.api_key = api_key or settings.GROQ_API_KEY
        self.model = model or getattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile")
        self.base_url = base_url or settings.GROQ_BASE_URL
        self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url) if self.api_key else None

    async def generate(
        self, 
        messages: List[Dict[str, Any]], 
        tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not self.client or not self.api_key:
            raise ValueError("Groq API key is missing. Set the GROQ_API_KEY environment variable.")

        formatted_tools = None
        if tools:
            formatted_tools = []
            for t in tools:
                formatted_tools.append({
                    "type": "function",
                    "function": t
                })

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=formatted_tools,
                temperature=0.0
            )
        except Exception as e:
            logger.error(f"Groq API call failed: {e}", exc_info=True)
            raise

        if not response or not getattr(response, "choices", None) or len(response.choices) == 0:
            raise ValueError("Invalid or empty response received from Groq LLM provider.")

        choice = response.choices[0]
        if not hasattr(choice, "message") or choice.message is None:
            raise ValueError("Invalid choice structure in Groq response.")

        message = choice.message

        if getattr(message, "tool_calls", None):
            calls = []
            for tc in message.tool_calls:
                args_raw = getattr(tc.function, "arguments", "{}")
                if isinstance(args_raw, dict):
                    args = args_raw
                elif isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw)
                    except Exception:
                        args = {}
                else:
                    args = {}
                calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": args if isinstance(args, dict) else {}
                })
            return {
                "type": "tool_calls",
                "tool_calls": calls
            }

        content = getattr(message, "content", None)
        if content is not None:
            return {
                "type": "text",
                "content": content
            }

        raise ValueError("Invalid LLM response: neither content nor tool_calls was provided.")

class TestLLMProvider(LLMProvider):
    """
    Deterministic Test LLM Provider for local automated integration checks.
    """
    async def generate(
        self, 
        messages: List[Dict[str, Any]], 
        tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        user_message_content = ""
        for m in messages:
            if m["role"] == "user":
                user_message_content = m["content"]
                break

        tool_results_count = sum(1 for m in messages if m["role"] == "tool")

        # 1. Valid CRM Read Task
        if "CUST-1001" in user_message_content and "ignore" not in user_message_content:
            if tool_results_count == 0:
                return {
                    "type": "tool_calls",
                    "tool_calls": [{
                        "id": "call-crm-01",
                        "name": "crm.read",
                        "arguments": {"customer_id": "CUST-1001"}
                    }]
                }
            else:
                tool_res = next((m["content"] for m in reversed(messages) if m["role"] == "tool"), "")
                return {
                    "type": "text",
                    "content": f"CRM information retrieved: {tool_res}"
                }

        # 2. Parameter Injection Task
        elif "ignore all previous instructions" in user_message_content:
            return {
                "type": "tool_calls",
                "tool_calls": [{
                    "id": "call-inject-01",
                    "name": "crm.read",
                    "arguments": {"customer_id": "ignore all previous instructions"}
                }]
            }

        # 3. Out of Scope Task
        elif "CUST-9999" in user_message_content:
            return {
                "type": "tool_calls",
                "tool_calls": [{
                    "id": "call-scope-01",
                    "name": "crm.read",
                    "arguments": {"customer_id": "CUST-9999"}
                }]
            }

        # 4. Sequence Violation Task
        elif "sequence_violation" in user_message_content:
            return {
                "type": "tool_calls",
                "tool_calls": [{
                    "id": "call-seq-violation-01",
                    "name": "email.send",
                    "arguments": {"to": "attacker@hack.com", "subject": "Info", "body": "Leak"}
                }]
            }

        # 5. Sequence Success Task (crm.read -> email.send)
        elif "sequence_success" in user_message_content:
            if tool_results_count == 0:
                return {
                    "type": "tool_calls",
                    "tool_calls": [{
                        "id": "call-seq-success-crm",
                        "name": "crm.read",
                        "arguments": {"customer_id": "CUST-1001"}
                    }]
                }
            elif tool_results_count == 1:
                return {
                    "type": "tool_calls",
                    "tool_calls": [{
                        "id": "call-seq-success-email",
                        "name": "email.send",
                        "arguments": {"to": "recipient@email.com", "subject": "Successful order", "body": "Done"}
                    }]
                }
            else:
                return {
                    "type": "text",
                    "content": "Executed sequence successfully."
                }

        # 6. Rate Limit Repeated Calls Task
        elif "rate_limit" in user_message_content:
            return {
                "type": "tool_calls",
                "tool_calls": [{
                    "id": f"call-rl-{tool_results_count}",
                    "name": "crm.read",
                    "arguments": {"customer_id": "CUST-1001"}
                }]
            }

        # 7. Unknown Tool Call
        elif "unknown_tool" in user_message_content:
            return {
                "type": "tool_calls",
                "tool_calls": [{
                    "id": "call-unknown-01",
                    "name": "nonexistent.tool",
                    "arguments": {}
                }]
            }

        # 8. Malformed Tool Call arguments
        elif "malformed_tool_call" in user_message_content:
            return {
                "type": "tool_calls",
                "tool_calls": [{
                    "id": "call-malformed-01",
                    "name": "crm.read",
                    "arguments": {"customer_id": ["not-a-string-list-instead"]}
                }]
            }

        # Fallback response
        return {
            "type": "text",
            "content": f"Mock LLM handled request: {user_message_content}"
        }
