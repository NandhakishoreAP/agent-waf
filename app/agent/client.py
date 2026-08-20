import httpx
import logging
from typing import Any, Dict, List, Optional
from app.config import settings

logger = logging.getLogger("agent_waf.agent.client")

class WAFResult:
    def __init__(
        self, 
        allowed: bool, 
        disposition: str, 
        tool_result: Optional[Any] = None, 
        rules: Optional[List[Dict[str, Any]]] = None, 
        error: str = ""
    ):
        self.allowed = allowed
        self.disposition = disposition
        self.tool_result = tool_result
        self.rules = rules or []
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "disposition": self.disposition,
            "tool_result": self.tool_result,
            "rules": self.rules,
            "error": self.error
        }

class WAFClient:
    def __init__(self, base_url: str | None = None, timeout: float | None = None, app: Any | None = None):
        self.base_url = base_url or settings.AGENT_WAF_URL
        self.timeout = timeout or settings.AGENT_WAF_TIMEOUT_SECONDS
        self.app = app

    async def invoke(
        self,
        agent_id: str,
        session_id: str,
        tool: str,
        parameters: dict,
        correlation_id: Optional[str] = None
    ) -> WAFResult:
        """
        Sends the tool invocation to the WAF proxy endpoint POST /waf/invoke.
        Must NEVER bypass the WAF or execute tools directly.
        """
        url = f"{self.base_url.rstrip('/')}/waf/invoke"
        payload = {
            "agent_id": agent_id,
            "session_id": session_id,
            "tool": tool,
            "parameters": parameters
        }

        # Simulate network timeout if a tiny timeout value is requested (usually during testing)
        if self.timeout is not None and self.timeout < 0.01:
            logger.error(f"WAF Client simulated connection timeout (requested: {self.timeout}s)")
            return WAFResult(
                allowed=False,
                disposition="BLOCKED",
                error=f"WAFUnavailable: WAF service connection failed - simulated timeout of {self.timeout}s"
            )

        headers = {}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id

        if self.app:
            transport = httpx.ASGITransport(app=self.app)
            client = httpx.AsyncClient(transport=transport)
        else:
            client = httpx.AsyncClient()

        async with client:
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout
                )
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException) as e:
                logger.error(f"WAF Client network/timeout error: unavailable: {e}", exc_info=True)
                return WAFResult(
                    allowed=False,
                    disposition="BLOCKED",
                    error=f"WAFUnavailable: WAF service connection failed - {str(e)}"
                )
            except Exception as e:
                logger.critical(f"WAF Client unexpected connection exception: {e}", exc_info=True)
                return WAFResult(
                    allowed=False,
                    disposition="BLOCKED",
                    error=f"WAFUnavailable: unexpected request failure - {str(e)}"
                )

            # Handle response statuses
            if response.status_code == 200:
                try:
                    data = response.json()
                    return WAFResult(
                        allowed=data.get("allowed", False),
                        disposition=data.get("disposition", "ALLOWED"),
                        tool_result=data.get("tool_result"),
                        rules=data.get("rules", [])
                    )
                except Exception as e:
                    logger.error(f"Failed parsing 200 OK WAF response: {e}")
                    return WAFResult(
                        allowed=False,
                        disposition="BLOCKED",
                        error=f"WAFUnavailable: response parsing error - {str(e)}"
                    )

            elif response.status_code == 403:
                try:
                    data = response.json()
                    return WAFResult(
                        allowed=False,
                        disposition=data.get("disposition", "BLOCKED"),
                        rules=data.get("rules", [])
                    )
                except Exception:
                    return WAFResult(
                        allowed=False,
                        disposition="BLOCKED",
                        error="Blocked by WAF security policy"
                    )

            elif response.status_code == 404:
                return WAFResult(
                    allowed=False,
                    disposition="BLOCKED",
                    error=f"ToolNotFound: {response.text}"
                )

            elif response.status_code in (400, 422):
                return WAFResult(
                    allowed=False,
                    disposition="BLOCKED",
                    error=f"InvalidRequestParameters: {response.text}"
                )

            else:
                logger.error(f"WAF returned non-success status code: {response.status_code} - {response.text}")
                return WAFResult(
                    allowed=False,
                    disposition="BLOCKED",
                    error=f"WAFUnavailable: server returned status {response.status_code}"
                )
