import time
import asyncio
from typing import Dict, Any, Optional, List
from sqlalchemy import select, func
from app.rules.base import BaseRuleEngine, EvaluationResult

_DB_LOCK = asyncio.Lock()

class ToolScopeEngine(BaseRuleEngine):
    async def evaluate(
        self,
        tool_name: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        db_session: Optional[Any] = None
    ) -> EvaluationResult:
        if not self.enabled or not context:
            return EvaluationResult(
                rule_type="tool_scope",
                rule_name=self.rule_name,
                action="ALLOW",
                triggered=False
            )

        declared_scope: List[str] = context.get("declared_scope", [])
        if declared_scope and tool_name not in declared_scope and "*" not in declared_scope:
            return EvaluationResult(
                rule_type="tool_scope",
                rule_name=self.rule_name,
                action="BLOCK",
                triggered=True,
                reason=f"Tool '{tool_name}' is not in declared scope: {declared_scope}"
            )

        return EvaluationResult(
            rule_type="tool_scope",
            rule_name=self.rule_name,
            action="ALLOW",
            triggered=False
        )

class RateLimitEngine(BaseRuleEngine):
    async def evaluate(
        self,
        tool_name: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        db_session: Optional[Any] = None
    ) -> EvaluationResult:
        if not self.enabled:
            return EvaluationResult(
                rule_type="rate_limit",
                rule_name=self.rule_name,
                action="ALLOW",
                triggered=False
            )

        return EvaluationResult(
            rule_type="rate_limit",
            rule_name=self.rule_name,
            action="ALLOW",
            triggered=False
        )
