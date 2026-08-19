import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import WAFPolicy

logger = logging.getLogger("agent_waf.rules.engine")

# Final Disposition Enumeration
class FinalDisposition(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    SHADOW_BLOCKED = "SHADOW_BLOCKED"

# Rule Evaluation Model
class RuleEvaluation(BaseModel):
    rule: str
    passed: bool
    reason: str

# Tool Invocation Context
class ToolInvocationContext(BaseModel):
    agent_id: str
    session_id: str
    tool_name: str
    parameters: Dict[str, Any]
    session_context: Dict[str, Any]

    model_config = ConfigDict(frozen=True)

# Common Rule Interface
class BaseRule(ABC):
    @abstractmethod
    async def evaluate(self, context: ToolInvocationContext, policy: WAFPolicy, db: AsyncSession) -> RuleEvaluation:
        """Evaluate the rule against the invocation context and the current policy."""
        pass

# Rule Engine Result
class RuleEngineResult(BaseModel):
    evaluations: List[RuleEvaluation]
    final_disposition: FinalDisposition

# Custom Exception for Rule Failures (Fail-Closed)
class RuleEvaluationError(Exception):
    """Raised when a security rule fails to execute properly."""
    pass

def _get_rule_order(rule: BaseRule) -> int:
    """
    Returns the deterministic order index for rule execution:
    1. rate_limit
    2. parameter_validation
    3. data_scope
    4. sequence
    """
    class_name = rule.__class__.__name__
    if class_name == "RateLimitRule":
        return 1
    elif class_name == "ParameterValidationRule":
        return 2
    elif class_name == "DataScopeRule":
        return 3
    elif class_name == "SequenceRule":
        return 4
    return 5

class RuleEngine:
    def __init__(self, policy: WAFPolicy, rules: List[BaseRule]):
        self.policy = policy
        # Enforce deterministic order
        self.rules = sorted(rules, key=_get_rule_order)

    async def evaluate(self, context: ToolInvocationContext, db: AsyncSession) -> RuleEngineResult:
        evaluations: List[RuleEvaluation] = []
        all_passed = True

        for rule in self.rules:
            try:
                evaluation = await rule.evaluate(context, self.policy, db)
                evaluations.append(evaluation)
                if not evaluation.passed:
                    all_passed = False
            except Exception as e:
                logger.error(f"Rule execution error in {rule.__class__.__name__}: {e}", exc_info=True)
                # Fail-closed: raise RuleEvaluationError to prevent allowing unsafe requests
                raise RuleEvaluationError(f"Security rule {rule.__class__.__name__} failed execution: {str(e)}") from e

        # Determine final disposition based on rules and policy mode
        if all_passed:
            final_disposition = FinalDisposition.ALLOWED
        else:
            if self.policy.mode == "shadow":
                final_disposition = FinalDisposition.SHADOW_BLOCKED
            else:
                final_disposition = FinalDisposition.BLOCKED

        return RuleEngineResult(
            evaluations=evaluations,
            final_disposition=final_disposition
        )
