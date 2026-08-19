import logging
from typing import Callable, Any, Dict, Awaitable

logger = logging.getLogger("agent_waf.tools.registry")

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Callable[[Dict[str, Any]], Awaitable[Any]]] = {}

    def register(self, name: str, handler: Callable[[Dict[str, Any]], Awaitable[Any]]) -> None:
        """Register a tool name with its handler."""
        if not name:
            raise ValueError("Tool name cannot be empty")
        self._tools[name] = handler
        logger.info(f"Registered tool: {name}")

    def exists(self, name: str) -> bool:
        """Check if a tool exists in the registry."""
        return name in self._tools

    def get(self, name: str) -> Callable[[Dict[str, Any]], Awaitable[Any]]:
        """Retrieve a registered tool's handler."""
        return self._tools.get(name)

    async def execute(self, name: str, parameters: Dict[str, Any]) -> Any:
        """Execute a registered tool with parameters."""
        handler = self.get(name)
        if not handler:
            raise KeyError(f"Tool {name} not found")
        return await handler(parameters)

# Global registry instance
registry = ToolRegistry()

# --- Sample Tool Implementations ---

async def crm_read_handler(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    crm.read simulation tool.
    Input:
      - customer_id: str
    """
    cust_id = parameters.get("customer_id")
    if not cust_id:
        raise ValueError("Missing required customer_id parameter")
    # Return a deterministic customer record
    return {
        "customer_id": cust_id,
        "name": "Acme Corp",
        "email": "contact@acme.com",
        "status": "active"
    }

async def email_send_handler(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    email.send simulation tool.
    Input:
      - to: str
      - subject: str
      - body: str
    """
    recipient = parameters.get("to")
    if not recipient:
        raise ValueError("Missing required 'to' parameter")
    return {
        "status": "sent",
        "recipient": recipient,
        "message_id": "msg-xyz123"
    }

async def db_backup_check_handler(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    db.backup_check simulation tool.
    """
    return {
        "status": "ready",
        "last_backup": "2026-08-19T12:00:00Z"
    }

async def db_delete_handler(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    db.delete simulation tool.
    Input:
      - record_count: int
    """
    count = parameters.get("record_count", 0)
    return {
        "status": "deleted",
        "records_removed": count
    }

# Register the standard tools
registry.register("crm.read", crm_read_handler)
registry.register("email.send", email_send_handler)
registry.register("db.backup_check", db_backup_check_handler)
registry.register("db.delete", db_delete_handler)
